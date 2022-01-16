"""
https://github.com/vikramarsid/msg_parser

Copyright (c) 2009-2018 Vikram Arsid <vikramarsid@gmail.com>

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of
      conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, this list
   of conditions and the following disclaimer in the documentation and/or other materials
   provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.

"""
from __future__ import print_function

import base64
# -*- coding: utf-8 -*-
import codecs
import email
import email.utils
import logging
import os
import quopri
import re
import tempfile
from datetime import datetime, timedelta
# coding=utf-8
from email import encoders
from email.header import Header
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from struct import unpack

import chardet  # type: ignore
from olefile import OleFileIO, isOleFile

from parse_emails.common import convert_to_unicode
from parse_emails.constants import (DEFAULT_ENCODING, MAX_DEPTH_CONST,
                                    PROPS_ID_MAP, REGEX_EMAIL, USER_ENCODING)

MIME_ENCODED_WORD = re.compile(r'(.*)=\?(.+)\?([B|Q])\?(.+)\?=(.*)')  # guardrails-disable-line

DATA_TYPE_MAP = {
    "0x0000": "PtypUnspecified",
    "0x0001": "PtypNull",
    "0x0002": "PtypInteger16",
    "0x0003": "PtypInteger32",
    "0x0004": "PtypFloating32",
    "0x0005": "PtypFloating64",
    "0x0006": "PtypCurrency",
    "0x0007": "PtypFloatingTime",
    "0x000A": "PtypErrorCode",
    "0x000B": "PtypBoolean",
    "0x000D": "PtypObject",
    "0x0014": "PtypInteger64",
    "0x001E": "PtypString8",
    "0x001F": "PtypString",
    "0x0040": "PtypTime",
    "0x0048": "PtypGuid",
    "0x00FB": "PtypServerId",
    "0x00FD": "PtypRestriction",
    "0x00FE": "PtypRuleAction",
    "0x0102": "PtypBinary",
    "0x1002": "PtypMultipleInteger16",
    "0x1003": "PtypMultipleInteger32",
    "0x1004": "PtypMultipleFloating32",
    "0x1005": "PtypMultipleFloating64",
    "0x1006": "PtypMultipleCurrency",
    "0x1007": "PtypMultipleFloatingTime",
    "0x1014": "PtypMultipleInteger64",
    "0x101F": "PtypMultipleString",
    "0x101E": "PtypMultipleString8",
    "0x1040": "PtypMultipleTime",
    "0x1048": "PtypMultipleGuid",
    "0x1102": "PtypMultipleBinary"
}

EMBEDDED_MSG_HEADER_SIZE = 24


def handle_msg(file_path, file_name, parse_only_headers=False, max_depth=3):
    if max_depth == 0:
        return None, []

    msg = MsOxMessage(file_path)
    if not msg:
        raise Exception("Could not parse msg file!")

    msg_dict = msg.as_dict(max_depth)
    mail_format_type = get_msg_mail_format(msg_dict)
    headers, headers_map = create_headers_map(msg_dict.get('Headers'))

    if parse_only_headers:
        return {"HeadersMap": headers_map}, []

    attached_emails_emls, attachments_data = save_attachments(msg.get_all_attachments(), file_name, max_depth - 1)
    # add eml attached emails

    attached_emails_msg = msg.get_attached_emails_hierarchy(max_depth - 1)

    email_data = {
        'To': msg_dict['To'],
        'CC': msg_dict['CC'],
        'From': msg_dict['From'],
        'Subject': headers_map.get('Subject') if headers_map.get('Subject') else msg_dict['Subject'],
        'HTML': msg_dict['HTML'],
        'Text': msg_dict['Text'],
        'Headers': headers,
        'HeadersMap': headers_map,
        'Attachments': msg_dict.get('Attachments'),
        'AttachmentsData': attachments_data,
        'Format': mail_format_type,
        'Depth': MAX_DEPTH_CONST - max_depth,
        'FileName': file_name
    }
    return email_data, attached_emails_emls + attached_emails_msg


class MsOxMessage(object):
    """
     Base class for Microsoft Message Object
    """

    def __init__(self, msg_file_path):
        self.msg_file_path = msg_file_path
        self.include_attachment_data = False

        if not self.is_valid_msg_file():
            raise Exception("Invalid file provided, please provide valid Microsoft Outlook MSG file.")

        ole_file = None
        try:
            ole_file = OleFileIO(msg_file_path)

            # process directory entries
            ole_root = ole_file.root
            kids_dict = ole_root.kids_dict

            self._message = Message(kids_dict)

        finally:
            if ole_file is not None:
                ole_file.close()

    def as_dict(self, max_depth):
        return self._message.as_dict(max_depth)

    def get_email_mime_content(self):
        email_obj = EmailFormatter(self)
        return email_obj.build_email()

    def save_email_file(self, file_path):
        email_obj = EmailFormatter(self)
        email_obj.save_file(file_path)
        return True

    def get_attached_emails_hierarchy(self, max_depth):
        return self._message.get_attached_emails_hierarchy(max_depth)

    def is_valid_msg_file(self):
        if not os.path.exists(self.msg_file_path):
            return False

        if not isOleFile(self.msg_file_path):
            return False

        return True

    def get_all_attachments(self):
        return self._message.get_all_attachments()


def get_msg_mail_format(msg_dict):
    try:
        return msg_dict.get('Headers', 'Content-type:').split('Content-type:')[1].split(';')[0]
    except Exception as e:
        logging.debug('Got exception while trying to get msg mail format - {}'.format(str(e)))
        return ''


def create_headers_map(msg_dict_headers):
    headers = list()  # type: list
    headers_map = dict()  # type: dict

    if not msg_dict_headers:
        return headers, headers_map

    header_key = 'initial key'
    header_value = 'initial header'
    for header in msg_dict_headers.split('\n'):
        if is_valid_header_to_parse(header):
            if not header[0] == ' ' and not header[0] == '\t':
                if header_value != 'initial header':
                    header_value = convert_to_unicode(header_value)
                    headers.append(
                        {
                            'name': header_key,
                            'value': header_value
                        }
                    )

                    if header_key in headers_map:
                        # in case there is already such header
                        # then add that header value to value array
                        if not isinstance(headers_map[header_key], list):
                            # convert the existing value to array
                            headers_map[header_key] = [headers_map[header_key]]

                        # add the new value to the value array
                        headers_map[header_key].append(header_value)
                    else:
                        headers_map[header_key] = header_value

                header_words = header.split(' ', 1)

                header_key = header_words[0][:-1]
                header_value = ' '.join(header_words[1:])
                if not header_value == '' and header_value[-1] == ' ':
                    header_value = header_value[:-1]

            else:
                header_value += header[:-1] if header[-1:] == ' ' else header

    return headers, headers_map


def save_attachments(attachments, root_email_file_name, max_depth):
    attached_emls = []
    attachments_data = []

    for attachment in attachments:
        if attachment.data is not None:
            display_name = attachment.DisplayName if attachment.DisplayName else attachment.AttachFilename
            display_name = display_name if display_name else ''

            attachments_data.append({
                "Name": display_name,
                "Content-ID": attachment.AttachContentId,
                "FileData": attachment.data
            })

            name_lower = display_name.lower()
            if max_depth > 0 and (name_lower.endswith(".eml") or name_lower.endswith('.p7m')):
                tf = tempfile.NamedTemporaryFile(delete=False)

                try:
                    tf.write(attachment.data)
                    tf.close()

                    inner_eml, attached_inner_emails = handle_eml(tf.name, file_name=root_email_file_name,
                                                                  max_depth=max_depth)
                    if inner_eml:
                        attached_emls.append(inner_eml)
                    if attached_inner_emails:
                        attached_emls.extend(attached_inner_emails)
                finally:
                    os.remove(tf.name)

    return attached_emls, attachments_data


class DataModel(object):

    def __init__(self):
        self.data_type_name = None

    @staticmethod
    def lookup_data_type_name(data_type):
        return DATA_TYPE_MAP.get(data_type)

    def get_value(self, data_value, data_type_name=None, data_type=None):

        if data_type_name:
            self.data_type_name = data_type_name
        elif data_type:
            self.data_type_name = self.lookup_data_type_name(data_type)
        else:
            raise Exception("required arguments not provided to the constructor of the class.")

        if not hasattr(self, self.data_type_name):
            return None
        value = getattr(self, self.data_type_name)(data_value)
        return value

    @staticmethod
    def PtypUnspecified(data_value):
        return data_value

    @staticmethod
    def PtypNull(data_value):
        return None

    @staticmethod
    def PtypInteger16(data_value):
        return int(data_value.encode('hex'), 16)

    @staticmethod
    def PtypInteger32(data_value):
        return int(data_value.encode('hex'), 32)

    @staticmethod
    def PtypFloating32(data_value):
        return unpack('f', data_value)[0]

    @staticmethod
    def PtypFloating64(data_value):
        return unpack('d', data_value)[0]

    @staticmethod
    def PtypCurrency(data_value):
        return data_value

    @staticmethod
    def PtypFloatingTime(data_value):
        return data_value

    @staticmethod
    def PtypErrorCode(data_value):
        return unpack('I', data_value)[0]

    @staticmethod
    def PtypBoolean(data_value):
        return unpack('B', data_value[0])[0] != 0

    @staticmethod
    def PtypObject(data_value):
        return data_value

    @staticmethod
    def PtypInteger64(data_value):
        return unpack('q', data_value)[0]

    @staticmethod
    def PtypString8(data_value):
        return DataModel.PtypString(data_value)

    @staticmethod
    def PtypString(data_value):
        if data_value:
            try:
                if USER_ENCODING:
                    logging.debug('Using argument user_encoding: {} to decode parsed message.'.format(USER_ENCODING))
                    return data_value.decode(USER_ENCODING, errors="ignore")
                res = chardet.detect(data_value)
                enc = res['encoding'] or 'ascii'  # in rare cases chardet fails to detect and return None as encoding
                if enc != 'ascii':
                    if enc.lower() == 'windows-1252' and res['confidence'] < 0.9:

                        enc = DEFAULT_ENCODING if DEFAULT_ENCODING else 'windows-1250'
                        logging.debug('Encoding detection confidence below threshold {}, '
                                      'switching encoding to "{}"'.format(res, enc))

                    temp = data_value
                    data_value = temp.decode(enc, errors='ignore')
                    if '\x00' in data_value:
                        logging.debug('None bytes found on encoded string, will try use utf-16-le '
                                      'encoding instead')
                        data_value = temp.decode("utf-16-le", errors="ignore")

                elif b'\x00' not in data_value:
                    data_value = data_value.decode("ascii", errors="ignore")
                else:
                    data_value = data_value.decode("utf-16-le", errors="ignore")

            except UnicodeDecodeError:
                data_value = data_value.decode("utf-16-le", errors="ignore")

        if isinstance(data_value, (bytes, bytearray)):
            data_value = data_value.decode('utf-8')

        return data_value

    @staticmethod
    def PtypTime(data_value):
        return get_time(data_value)

    @staticmethod
    def PtypGuid(data_value):
        return data_value

    @staticmethod
    def PtypServerId(data_value):
        return data_value

    @staticmethod
    def PtypRestriction(data_value):
        return data_value

    @staticmethod
    def PtypRuleAction(data_value):
        return data_value

    @staticmethod
    def PtypBinary(data_value):
        # if data_value and '\x00' in data_value:
        #     data_value = data_value.replace('\x00', '')
        return data_value

    @staticmethod
    def PtypMultipleInteger16(data_value):
        entry_count = len(data_value) / 2
        return [unpack('h', data_value[i * 2:(i + 1) * 2])[0] for i in range(entry_count)]

    @staticmethod
    def PtypMultipleInteger32(data_value):
        entry_count = len(data_value) / 4
        return [unpack('i', data_value[i * 4:(i + 1) * 4])[0] for i in range(entry_count)]

    @staticmethod
    def PtypMultipleFloating32(data_value):
        entry_count = len(data_value) / 4
        return [unpack('f', data_value[i * 4:(i + 1) * 4])[0] for i in range(entry_count)]

    @staticmethod
    def PtypMultipleFloating64(data_value):
        entry_count = len(data_value) / 8
        return [unpack('d', data_value[i * 8:(i + 1) * 8])[0] for i in range(entry_count)]

    @staticmethod
    def PtypMultipleCurrency(data_value):
        return data_value

    @staticmethod
    def PtypMultipleFloatingTime(data_value):
        entry_count = len(data_value) / 8
        return [get_floating_time(data_value[i * 8:(i + 1) * 8]) for i in range(entry_count)]

    @staticmethod
    def PtypMultipleInteger64(data_value):
        entry_count = len(data_value) / 8
        return [unpack('q', data_value[i * 8:(i + 1) * 8])[0] for i in range(entry_count)]

    @staticmethod
    def PtypMultipleString(data_value):
        return DataModel.PtypString(data_value)

    @staticmethod
    def PtypMultipleString8(data_value):
        return data_value

    @staticmethod
    def PtypMultipleTime(data_value):
        entry_count = len(data_value) / 8
        return [get_time(data_value[i * 8:(i + 1) * 8]) for i in range(entry_count)]

    @staticmethod
    def PtypMultipleGuid(data_value):
        entry_count = len(data_value) / 16
        return [data_value[i * 16:(i + 1) * 16] for i in range(entry_count)]

    @staticmethod
    def PtypMultipleBinary(data_value):
        return data_value


class Message(object):
    """
     Class to store Message properties
    """

    def __init__(self, directory_entries, parent_directory_path=None):

        if parent_directory_path is None:
            parent_directory_path = []

        self._streams = self._process_directory_entries(directory_entries)
        self.embedded_messages = []  # type: list
        self._data_model = DataModel()
        self._parent_directory_path = parent_directory_path
        self._nested_attachments_depth = 0
        self.properties = self._get_properties()
        self.attachments = self._get_attachments()
        self.recipients = self._get_recipients()

        self._set_properties()
        self._set_attachments()
        self._set_recipients()
        self._embed_images_to_html_body()

    def _embed_images_to_html_body(self):
        # embed images into html body
        if self.attachments and self.html:
            for attachment in self.attachments:
                if attachment.AttachContentId and f'src="cid:{attachment.AttachContentId}"' in self.html:
                    img_base64 = base64.b64encode(attachment.data).decode('ascii')
                    self.html = self.html.replace(f'src="cid:{attachment.AttachContentId}"',
                                                  f'src="data:image/png;base64, {img_base64}"')

    def _get_attachments_names(self):
        names = []
        for attachment in self.attachments:
            names.append(attachment.DisplayName or attachment.Filename)

        return names

    def get_all_attachments(self):
        attachments = self.attachments

        for embedded_message in self.embedded_messages:
            attachments.extend(embedded_message.get_all_attachments())

        return attachments

    def as_dict(self, max_depth):
        if max_depth == 0:
            return None

        def join(arr):
            if isinstance(arr, list):
                arr = [item for item in arr if item is not None]
                return ",".join(arr)

            return ""

        cc = None
        if self.cc is not None:
            cc = join([extract_address(cc) for cc in self.cc])  # noqa: F812

        bcc = None
        if self.bcc is not None:
            bcc = join([extract_address(bcc) for bcc in self.bcc])  # noqa

        recipients = None
        if self.to is not None:
            recipients = join([extract_address(recipient.EmailAddress) for recipient in self.recipients])  # noqa

        sender = None
        if self.sender is not None:
            sender = join([extract_address(sender) for sender in self.sender])  # noqa

        html = self.html
        if not html:
            html = self.body

        message_dict = {
            'Attachments': join(self._get_attachments_names()),
            'CC': cc,
            'BCC': bcc,
            'To': recipients,
            'From': sender,
            'Subject': self.subject,
            'Text': self.properties.get('Body') if self.properties.get('Body') else str(self.body),
            'HTML': html,
            'Headers': str(self.header) if self.header is not None else None,
            'HeadersMap': self.header_dict,
            'Depth': MAX_DEPTH_CONST - max_depth
        }

        return message_dict

    def get_attached_emails_hierarchy(self, max_depth):
        if max_depth == 0:
            return []

        attached_emails = []
        for embedded_message in self.embedded_messages:
            attached_emails.append(embedded_message.as_dict(max_depth))
            attached_emails.extend(embedded_message.get_attached_emails_hierarchy(max_depth - 1))

        return attached_emails

    def _set_property_stream_info(self, ole_file, header_size):
        property_dir_entry = ole_file.openstream('__properties_version1.0')
        version_stream_data = property_dir_entry.read()

        if not version_stream_data:
            raise Exception("Invalid MSG file provided, 'properties_version1.0' stream data is empty.")

        if version_stream_data:

            if header_size >= EMBEDDED_MSG_HEADER_SIZE:

                properties_metadata = unpack('8sIIII', version_stream_data[:24])
                if not properties_metadata or not len(properties_metadata) >= 5:
                    raise Exception("'properties_version1.0' stream data is corrupted.")
                self.next_recipient_id = properties_metadata[1]
                self.next_attachment_id = properties_metadata[2]
                self.recipient_count = properties_metadata[3]
                self.attachment_count = properties_metadata[4]

            if (len(version_stream_data) - header_size) % 16 != 0:
                raise Exception('Property Stream size less header is not exactly divisible by 16')

            self.property_entries_count = (len(version_stream_data) - header_size) / 16

    @staticmethod
    def _process_directory_entries(directory_entries):

        streams = {
            "properties": {},
            "recipients": {},
            "attachments": {}
        }  # type: dict
        for name, stream in directory_entries.items():
            # collect properties
            if "__substg1.0_" in name:
                streams["properties"][name] = stream

            # collect attachments
            elif "__attach_" in name:
                streams["attachments"][name] = stream.kids

            # collect recipients
            elif "__recip_" in name:
                streams["recipients"][name] = stream.kids

            # unknown stream name
            else:
                continue

        return streams

    def _get_properties(self):

        directory_entries = self._streams.get("properties")
        directory_name_filter = "__substg1.0_"
        property_entries = {}
        for directory_name, directory_entry in directory_entries.items():

            if directory_name_filter not in directory_name:
                continue

            if not directory_entry:
                continue

            if isinstance(directory_entry, list):
                directory_values = {}  # type: dict
                for property_entry in directory_entry:
                    property_data = self._get_property_data(directory_name, property_entry, is_list=True)
                    if property_data:
                        directory_values.update(property_data)

                property_entries[directory_name] = directory_values
            else:
                property_data = self._get_property_data(directory_name, directory_entry)
                if property_data:
                    property_entries.update(property_data)
        return property_entries

    def _get_recipients(self):

        directory_entries = self._streams.get("recipients")
        directory_name_filter = "__recip_version1.0_"
        recipient_entries = {}
        for directory_name, directory_entry in directory_entries.items():

            if directory_name_filter not in directory_name:
                continue

            if not directory_entry:
                continue

            if isinstance(directory_entry, list):
                directory_values = {}  # type: dict
                for property_entry in directory_entry:
                    property_data = self._get_property_data(directory_name, property_entry, is_list=True)
                    if property_data:
                        directory_values.update(property_data)

                recipient_address = directory_values.get(
                    'EmailAddress', directory_values.get('SmtpAddress', directory_name)
                )
                recipient_entries[recipient_address] = directory_values
            else:
                property_data = self._get_property_data(directory_name, directory_entry)
                if property_data:
                    recipient_entries.update(property_data)
        return recipient_entries

    def _get_attachments(self):
        directory_entries = self._streams.get("attachments")
        directory_name_filter = "__attach_version1.0_"
        attachment_entries = {}
        for directory_name, directory_entry in directory_entries.items():
            if directory_name_filter not in directory_name:
                continue

            if not directory_entry:
                continue

            if isinstance(directory_entry, list):
                directory_values = {}
                for property_entry in directory_entry:

                    kids = property_entry.kids
                    if kids:
                        embedded_message = Message(
                            property_entry.kids_dict,
                            self._parent_directory_path + [directory_name, property_entry.name]
                        )

                        directory_values["EmbeddedMessage"] = {
                            "properties": embedded_message.properties,
                            "recipients": embedded_message.recipients,
                            "attachments": embedded_message.attachments
                        }
                        self.embedded_messages.append(embedded_message)

                    property_data = self._get_property_data(directory_name, property_entry, is_list=True)
                    if property_data:
                        directory_values.update(property_data)

                attachment_entries[directory_name] = directory_values

            else:
                property_data = self._get_property_data(directory_name, directory_entry)
                if property_data:
                    attachment_entries.update(property_data)
        return attachment_entries

    def _get_property_data(self, directory_name, directory_entry, is_list=False):
        directory_entry_name = directory_entry.name
        if is_list:
            stream_name = [directory_name, directory_entry_name]
        else:
            stream_name = [directory_entry_name]

        if self._parent_directory_path:
            stream_name = self._parent_directory_path + stream_name

        ole_file = directory_entry.olefile
        property_details = self._get_canonical_property_name(directory_entry_name)
        if not property_details:
            return None

        property_name = property_details.get("name")
        property_type = property_details.get("data_type")
        if not property_type:
            logging.debug('could not parse property type, skipping property "{}"'.format(property_details))
            return None

        try:
            raw_content = ole_file.openstream(stream_name).read()
        except IOError:
            raw_content = ''
        if not raw_content:
            logging.debug('Could not read raw content from stream "{}", '
                          'skipping property "{}"'.format(stream_name, property_details))
            return None

        property_value = self._data_model.get_value(raw_content, data_type=property_type)
        if property_value:
            property_detail = {property_name: property_value}
        else:
            property_detail = None  # type: ignore[assignment]

        return property_detail

    @staticmethod
    def _get_canonical_property_name(dir_entry_name):
        if not dir_entry_name:
            return None

        if "__substg1.0_" in dir_entry_name:
            name = dir_entry_name.replace("__substg1.0_", "")
            prop_name_id = "0x" + name[0:4]
            prop_details = PROPS_ID_MAP.get(prop_name_id)
            return prop_details

        return None

    def _set_properties(self):
        property_values = self.properties

        # setting generally required properties to easily access using MsOxMessage instance.
        self.subject = property_values.get("Subject")

        header = property_values.get("TransportMessageHeaders")
        self.header = parse_email_headers(header, True)
        self.header_dict = parse_email_headers(header) or {}

        self.created_date = property_values.get("CreationTime")
        self.received_date = property_values.get("ReceiptTime")

        sent_date = property_values.get("DeliverTime")
        if not sent_date:
            sent_date = self.header_dict.get("Date")
        self.sent_date = sent_date

        sender_address = self.header_dict.get("From")
        if not sender_address:
            sender_address = property_values.get("SenderRepresentingSmtpAddress")
        self.sender = sender_address

        reply_to_address = self.header_dict.get("Reply-To")
        if not reply_to_address:
            reply_to_address = property_values.get("ReplyRecipientNames")
        self.reply_to = reply_to_address

        self.message_id = property_values.get("InternetMessageId")

        to_address = self.header_dict.get("To")
        if not to_address:
            to_address = property_values.get("ReceivedRepresentingSmtpAddress")
            if not to_address:
                to_address = property_values.get("DisplayTo")

        self.to = to_address
        to_smpt_address = property_values.get("ReceivedRepresentingSmtpAddress")
        if not to_smpt_address:
            to_smpt_address = [value for key, value in self.recipients.items()]
        self.to_address = to_smpt_address

        cc_address = self.header_dict.get("CC")
        # if cc_address:
        #     cc_address = [CONTROL_CHARS.sub(" ", cc_add) for cc_add in cc_address.split(",")]
        self.cc = cc_address

        bcc_address = self.header_dict.get("BCC")
        self.bcc = bcc_address

        # prefer HTMl over plain text
        self.html = property_values.get("Html")
        self.body = property_values.get("Body")

        if "RtfCompressed" in property_values:
            try:
                import compressed_rtf
            except ImportError:
                compressed_rtf = None
            if compressed_rtf:
                compressed_rtf_body = property_values['RtfCompressed']
                self.body = compressed_rtf.decompress(compressed_rtf_body)

                from RTFDE.deencapsulate import DeEncapsulator

                rtf_obj = DeEncapsulator(self.body)
                rtf_obj.deencapsulate()
                if rtf_obj.content_type == 'html':
                    self.html = rtf_obj.html

    def _set_recipients(self):
        recipients = self.recipients
        self.recipients = []
        for recipient_name, recipient in recipients.items():

            if self.to and recipient_name in self.to:
                recipient["RecipientType"] = "TO"

            if self.cc and recipient_name in self.cc:
                recipient["RecipientType"] = "CC"

            if self.bcc and recipient_name in self.bcc:
                recipient["RecipientType"] = "BCC"

            if self.reply_to and recipient_name in self.reply_to:
                recipient["RecipientType"] = "ReplyTo"

            self.recipients.append(Recipient(recipient))

    def _set_attachments(self):
        attachments = self.attachments
        self.attachments = [Attachment(attach) for attach in attachments.values()]

    def __repr__(self):
        return u'Message [%s]' % self.properties.get('InternetMessageId', self.properties.get("Subject"))


class EmailFormatter(object):
    def __init__(self, msg_object):
        self.msg_obj = msg_object
        self.message = MIMEMultipart()
        self.message.set_charset('utf-8')

    def build_email(self):

        # Setting Message ID
        self.message.set_param("Message-ID", self.msg_obj.message_id)

        # Encoding for unicode subject
        self.message['Subject'] = Header(self.msg_obj.subject, charset='UTF-8')

        # Setting Date Time
        # Returns a date string as specified by RFC 2822, e.g.: Fri, 09 Nov 2001 01:08:47 -0000
        self.message['Date'] = str(self.msg_obj.sent_date)

        # At least one recipient is required
        # Required fromAddress
        from_address = flatten_list(self.msg_obj.sender)
        if from_address:
            self.message['From'] = from_address

        to_address = flatten_list(self.msg_obj.header_dict.get("To"))
        if to_address:
            self.message['To'] = to_address

        cc_address = flatten_list(self.msg_obj.header_dict.get("CC"))
        if cc_address:
            self.message['CC'] = cc_address

        bcc_address = flatten_list(self.msg_obj.header_dict.get("BCC"))
        if bcc_address:
            self.message['BCC'] = bcc_address

        # Add reply-to
        reply_to = flatten_list(self.msg_obj.reply_to)
        if reply_to:
            self.message.add_header('reply-to', reply_to)
        else:
            self.message.add_header('reply-to', from_address)

        # Required Email body content
        body_content = self.msg_obj.body
        if body_content:
            if "<html>" in body_content:
                body_type = 'html'
            else:
                body_type = 'plain'

            body = MIMEText(_text=body_content, _subtype=body_type, _charset="UTF-8")
            self.message.attach(body)
        else:
            raise KeyError("Missing email body")

        # Add message preamble
        self.message.preamble = 'You will not see this in a MIME-aware mail reader.\n'

        # Optional attachments
        attachments = self.msg_obj.attachments
        if attachments:
            self._process_attachments(self.msg_obj.attachments)

        # composed email
        composed = self.message.as_string()

        return composed

    def save_file(self, file_path):

        eml_content = self.build_email()

        file_name = str(self.message['Subject']) + ".eml"

        eml_file_path = os.path.join(file_path, file_name)

        with codecs.open(eml_file_path, mode="wb+", encoding="utf-8") as eml_file:
            eml_file.write(eml_content.decode("utf-8"))

        return eml_file_path

    def _process_attachments(self, attachments):
        for attachment in attachments:
            ctype = attachment.AttachMimeTag
            data = attachment.data
            filename = attachment.DisplayName
            maintype, subtype = ctype.split('/', 1)

            if maintype == 'text' or "message" in maintype:
                attach = MIMEText(data, _subtype=subtype)
            elif maintype == 'image':
                attach = MIMEImage(data, _subtype=subtype)  # type: ignore[assignment]
            elif maintype == 'audio':
                attach = MIMEAudio(data, _subtype=subtype)  # type: ignore[assignment]
            else:
                attach = MIMEBase(maintype, subtype)  # type: ignore[assignment]
                attach.set_payload(data)

                # Encode the payload using Base64
                encoders.encode_base64(attach)
            # Set the filename parameter
            base_filename = os.path.basename(filename)
            attach.add_header('Content-ID', '<{}>'.format(base_filename))
            attach.add_header('Content-Disposition', 'attachment', filename=base_filename)
            self.message.attach(attach)


def is_valid_header_to_parse(header):
    return len(header) > 0 and not header == ' ' and 'From nobody' not in header


def recursive_convert_to_unicode(replace_to_utf):
    """Converts object into UTF-8 characters
    ignores errors
    Args:
        replace_to_utf (object): any object

    Returns:
        object converted to UTF-8
    """
    try:
        if isinstance(replace_to_utf, dict):
            return {recursive_convert_to_unicode(k): recursive_convert_to_unicode(v) for k, v in replace_to_utf.items()}
        if isinstance(replace_to_utf, list):
            return [recursive_convert_to_unicode(i) for i in replace_to_utf if i]
        if not replace_to_utf:
            return replace_to_utf
        return str(replace_to_utf, 'utf-8', 'ignore')
    except TypeError:
        return replace_to_utf


def get_time(data_value):
    return datetime(
        year=1601, month=1, day=1
    ) + timedelta(
        microseconds=unpack('q', data_value)[0] / 10.0
    )


def get_floating_time(data_value):
    return datetime(
        year=1899, month=12, day=30
    ) + timedelta(
        days=unpack('d', data_value)[0]
    )


def extract_address(s):
    if type(s) not in [str]:
        return s
    res = re.findall(REGEX_EMAIL, s)
    if res:
        return ', '.join(res)
    else:
        return s


def parse_email_headers(header, raw=False):
    if not header:
        return None

    headers = email.message_from_string(header)
    if raw:
        return headers

    email_address_headers = {  # type: ignore[var-annotated]
        "To": [],
        "From": [],
        "CC": [],
        "BCC": [],
        "Reply-To": [],
    }

    for addr in email_address_headers.keys():
        for (name, email_address) in email.utils.getaddresses(headers.get_all(addr, [])):
            email_address_headers[addr].append("{} <{}>".format(name, email_address))

    parsed_headers = dict(headers)
    parsed_headers.update(email_address_headers)

    return parsed_headers


class Recipient(object):
    """
     class to store recipient attributes
    """

    def __init__(self, recipients_properties):
        self.AddressType = recipients_properties.get("AddressType")
        self.Account = recipients_properties.get("Account")
        self.EmailAddress = recipients_properties.get("SmtpAddress")
        self.DisplayName = recipients_properties.get("DisplayName")
        self.ObjectType = recipients_properties.get("ObjectType")
        self.RecipientType = recipients_properties.get("RecipientType")

    def __repr__(self):
        return '{} ({})'.format(self.DisplayName, self.EmailAddress)


class Attachment(object):
    """
     class to store attachment attributes
    """

    def __init__(self, attachment_properties):

        self.DisplayName = attachment_properties.get("DisplayName")
        self.AttachEncoding = attachment_properties.get("AttachEncoding")
        self.AttachContentId = attachment_properties.get("AttachContentId")
        self.AttachMethod = attachment_properties.get("AttachMethod")
        self.AttachmentSize = format_size(attachment_properties.get("AttachmentSize"))
        self.AttachFilename = attachment_properties.get("AttachFilename")
        self.AttachLongFilename = attachment_properties.get("AttachLongFilename")
        if self.AttachLongFilename:
            self.Filename = self.AttachLongFilename
        else:
            self.Filename = self.AttachFilename
        if self.Filename:
            self.Filename = os.path.basename(self.Filename)
        else:
            self.Filename = '[NoFilename_Method%s]' % self.AttachMethod
        self.data = attachment_properties.get("AttachDataObject")
        self.AttachMimeTag = attachment_properties.get("AttachMimeTag", "application/octet-stream")
        self.AttachExtension = attachment_properties.get("AttachExtension")

    def __repr__(self):
        return '{} ({} / {})'.format(self.Filename, self.AttachmentSize, len(self.data or []))


def format_size(num, suffix='B'):
    if not num:
        return "unknown"
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "{:3.1f}{}{}".format(num, unit, suffix)
        num /= 1024.0
    return "{:.1f}{}{}".format(num, 'Yi', suffix)


def flatten_list(string_list):
    if string_list and isinstance(string_list, list):
        string = ",".join(string_list)
        return string
    return None


def mime_decode(word_mime_encoded):
    prefix, charset, encoding, encoded_text, suffix = word_mime_encoded.groups()
    if encoding.lower() == 'b':
        byte_string = base64.b64decode(encoded_text)
    elif encoding.lower() == 'q':
        byte_string = quopri.decodestring(encoded_text)
    return prefix + byte_string.decode(charset) + suffix
