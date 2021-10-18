from __future__ import print_function

import base64
import email
import email.utils
import logging
import os
import quopri
import re
import tempfile
from base64 import b64decode
from email import message_from_string
from email.parser import HeaderParser
from email.utils import getaddresses

from email_parser.constants import MAX_DEPTH_CONST, REGEX_EMAIL
# from common import convert_to_unicode
from email_parser.handle_msg import handle_msg

MIME_ENCODED_WORD = re.compile(r'(.*)=\?(.+)\?([B|Q])\?(.+)\?=(.*)')  # guardrails-disable-line
ENCODINGS_TYPES = {'utf-8', 'iso8859-1'}


def handle_eml(file_path, b64=False, file_name=None, parse_only_headers=False, max_depth=3, bom=False):
    global ENCODINGS_TYPES

    if max_depth == 0:
        return None, []

    with open(file_path, 'rb') as emlFile:

        file_data = emlFile.read()
        if b64:
            file_data = b64decode(file_data)
        if bom:
            # decode bytes taking into account BOM and re-encode to utf-8
            file_data = file_data.decode("utf-8-sig")

        if isinstance(file_data, bytes):
            file_data = file_data.decode('utf-8', 'ignore')

        parser = HeaderParser()
        headers = parser.parsestr(file_data)

        header_list = []
        headers_map = {}  # type: dict
        for item in headers.items():
            value = unfold(item[1])
            item_dict = {
                "name": item[0],
                "value": value
            }

            # old way to map headers
            header_list.append(item_dict)

            # new way to map headers - dictionary
            if item[0] in headers_map:
                # in case there is already such header
                # then add that header value to value array
                if not isinstance(headers_map[item[0]], list):
                    # convert the existing value to array
                    headers_map[item[0]] = [headers_map[item[0]]]

                # add the new value to the value array
                headers_map[item[0]].append(value)
            else:
                headers_map[item[0]] = value

        eml = message_from_string(file_data)
        if not eml:
            raise Exception("Could not parse eml file!")

        if parse_only_headers:
            return {"HeadersMap": headers_map}, []

        html = ''
        text = ''
        attachment_names = []

        attached_emails = []
        parts = [eml]

        while parts:
            part = parts.pop()
            if (part.is_multipart() or part.get_content_type().startswith('multipart')) \
                    and "attachment" not in part.get("Content-Disposition", ""):
                parts += [part_ for part_ in part.get_payload() if isinstance(part_, email.message.Message)]

            elif part.get_filename() or "attachment" in part.get("Content-Disposition", ""):

                attachment_file_name = get_attachment_filename(part)

                if "message/rfc822" in part.get("Content-Type", "") \
                        or ("application/octet-stream" in part.get("Content-Type", "") and
                            attachment_file_name.endswith(".eml")):

                    # .eml files
                    file_content = ""  # type: str
                    base64_encoded = "base64" in part.get("Content-Transfer-Encoding", "")

                    if isinstance(part.get_payload(), list) and len(part.get_payload()) > 0:
                        if attachment_file_name is None or attachment_file_name == "" or attachment_file_name == 'None':
                            # in case there is no filename for the eml
                            # we will try to use mail subject as file name
                            # Subject will be in the email headers
                            attachment_name = part.get_payload()[0].get('Subject', "no_name_mail_attachment")
                            attachment_file_name = f'{attachment_name}.eml'

                        file_content = part.get_payload()[0].as_string().strip()
                        if base64_encoded:
                            try:
                                file_content = b64decode(file_content)

                            except TypeError:
                                pass  # In case the file is a string, decode=True for get_payload is not working

                    elif isinstance(part.get_payload(), str):
                        file_content = part.get_payload(decode=True)
                    else:
                        logging.debug("found eml attachment with Content-Type=message/rfc822 but has no payload")

                    if file_content and max_depth - 1 > 0:
                        f = tempfile.NamedTemporaryFile(delete=False)
                        try:
                            if isinstance(file_content, str):
                                file_content = file_content.encode('utf-8')
                            f.write(file_content)
                            f.close()
                            inner_eml, inner_attached_emails = handle_eml(file_path=f.name,
                                                                          file_name=attachment_file_name,
                                                                          max_depth=max_depth - 1)
                            attached_emails.append(inner_eml)
                            attached_emails.extend(inner_attached_emails)

                        finally:
                            os.remove(f.name)
                    attachment_names.append(attachment_file_name)
                else:
                    # .msg and other files (png, jpeg)
                    if part.is_multipart() and max_depth - 1 > 0:
                        # email is DSN
                        msgs = part.get_payload()  # human-readable section
                        for i, individual_message in enumerate(msgs):

                            msg_info = decode_attachment_payload(individual_message)
                            attached_emails.append(msg_info)

                            attachment_file_name = individual_message.get_filename()
                            if attachment_file_name is None:
                                attachment_file_name = "unknown_file_name{}".format(i)

                            attachment_names.append(attachment_file_name)

                    else:
                        file_content = part.get_payload(decode=True)

                        if attachment_file_name.endswith(".msg") and max_depth - 1 > 0:
                            f = tempfile.NamedTemporaryFile(delete=False)
                            try:
                                f.write(file_content)
                                f.close()
                                inner_msg, inner_attached_emails = handle_msg(f.name, attachment_file_name, False,
                                                                              max_depth - 1)
                                attached_emails.append(inner_msg)
                                attached_emails.extend(inner_attached_emails)

                            finally:
                                os.remove(f.name)

                        attachment_names.append(attachment_file_name)

            elif part.get_content_type() == 'text/html':
                # This line replaces a new line that starts with `..` to a newline that starts with `.`
                # This is because SMTP duplicate dots for lines that start with `.` and get_payload() doesn't format
                # this correctly
                part.set_payload(part.get_payload().replace('=\r\n..', '=\r\n.'))
                html = decode_content(part)

            elif part.get_content_type() == 'text/plain':
                text = decode_content(part)
        email_data = None
        # if we are parsing a signed attachment there can be one of two options:
        # 1. it is 'multipart/signed' so it is probably a wrapper and we can ignore the outer "email"
        # 2. if it is 'multipart/signed' but has 'to' address so it is actually a real mail.
        if 'multipart/signed' not in eml.get_content_type() \
                or ('multipart/signed' in eml.get_content_type() and
                    (extract_address_eml(eml, 'to') or extract_address_eml(eml, 'from') or eml.get('subject'))):
            email_data = {
                'To': extract_address_eml(eml, 'to'),
                'CC': extract_address_eml(eml, 'cc'),
                'From': extract_address_eml(eml, 'from'),
                'Subject': eml['Subject'],
                'HTML': html,
                'Text': text,
                'Headers': header_list,
                'HeadersMap': headers_map,
                'Attachments': ','.join(attachment_names) if attachment_names else '',
                'AttachmentNames': attachment_names if attachment_names else [],
                'Format': eml.get_content_type(),
                'Depth': MAX_DEPTH_CONST - max_depth
            }
        return email_data, attached_emails


def unfold(s):
    r"""
    Remove folding whitespace from a string by converting line breaks (and any
    whitespace adjacent to line breaks) to a single space and removing leading
    & trailing whitespace.
    From: https://github.com/jwodder/headerparser/blob/master/headerparser/types.py#L39
    unfold('This is a \n folded string.\n')
    'This is a folded string.'
    :param string s: a string to unfold
    :rtype: string
    """
    return re.sub(r'[ \t]*[\r\n][ \t\r\n]*', ' ', s).strip(' ')


def decode_content(mime):
    """
      Decode content
    """
    charset = mime.get_content_charset()
    payload = mime.get_payload(decode=True)
    try:
        if payload:
            if charset == 'ascii':
                return payload.decode("ascii")
            else:
                return payload.decode("raw-unicode-escape")
        else:
            return ''

    except UnicodeDecodeError:
        payload = mime.get_payload()
        if isinstance(payload, str):
            return payload


def mime_decode(word_mime_encoded):
    prefix, charset, encoding, encoded_text, suffix = word_mime_encoded.groups()
    if encoding.lower() == 'b':
        byte_string = base64.b64decode(encoded_text)
    elif encoding.lower() == 'q':
        byte_string = quopri.decodestring(encoded_text, header=True)
    return prefix + byte_string.decode(charset) + suffix


def get_email_address(eml, entry):
    """
    This function gets email addresses from an eml object, i.e eml[entry].
    Args:
        eml : Email object.
        entry (str) : entry to look for in the email. i.e ('To', 'CC', 'From')
    Returns:
        res (str) : string of all required email addresses.
    """
    gel_all_values_from_email_by_entry = eml.get_all(entry, [])
    addresses = getaddresses(gel_all_values_from_email_by_entry)
    if addresses:
        res = [item[1] for item in addresses]
        res = ', '.join(res)
        if entry == 'from' and "\r\n" in gel_all_values_from_email_by_entry[0] and \
                    (not re.search(REGEX_EMAIL, res) or len(addresses) > 1):
            # this condition refers only to ['from'] header that does not have a valid email or have more then 1
            # fixed an issue where email['From'] had '\r\n'.
            # in order to solve, used replace_header() on email object,
            # and did again get_all() on the new format of ['from']
            original_value = eml['from']
            eml.replace_header('from', ' '.join(eml["from"].splitlines()))
            res = get_email_address(eml, entry)
            eml.replace_header('from', original_value)  # replace again to the original header (keep on BC)
        return res
    return ''


def extract_address_eml(eml, entry):
    """
    This function calls get_email_address in order to get required email addresses from email object.
    In addition, this function handles an edge case of '\r\n' in eml['from'] (as explained below).
    Args:
        eml : Email object.
        entry (str) : entry to look for in the email. i.e ('To', 'CC', 'From')
    Returns:
        res (str) : string of all required email addresses.
    """
    email_address = get_email_address(eml, entry)
    if email_address:
        return email_address
    else:
        return ''


def get_attachment_filename(part):
    attachment_file_name = None
    if part.get_filename():
        attachment_file_name = part.get_filename()

    elif attachment_file_name is None and part.get('filename'):
        attachment_file_name = os.path.normpath(part.get('filename'))
        if os.path.isabs(attachment_file_name):
            attachment_file_name = os.path.basename(attachment_file_name)
    else:
        for payload in part.get_payload():
            if payload.get_filename():
                attachment_file_name = payload.get_filename()
                break

    return attachment_file_name


def decode_attachment_payload(message):
    """Decodes a message from Base64, if fails will outputs its str(message)
    """
    msg = message.get_payload()
    try:
        # In some cases the body content is empty and cannot be decoded.
        msg_info = base64.b64decode(msg)
    except TypeError:
        msg_info = str(msg)
    return msg_info
