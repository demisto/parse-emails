import logging
import os
import traceback
from base64 import b64decode

import magic

from parse_emails.handle_eml import handle_eml
from parse_emails.handle_msg import handle_msg


class EmailParser(object):
    """
    The core class for the EmailParser.
    """

    def __init__(self, file_path, max_depth=3, parse_only_headers=False, file_info='', forced_encoding=None,
                 default_encoding=None):

        self._file_path = file_path
        self._file_type = self.get_file_type(file_info)
        self._file_name = os.path.basename(self._file_path)
        self._max_depth = max_depth
        self._parse_only_headers = parse_only_headers
        self._forced_encoding = forced_encoding
        self._default_encoding = default_encoding
        self._is_msg = self.check_if_is_msg()
        self._bom = False
        self.parsed_email = None

        if self._max_depth < 1:
            raise Exception('Minimum max_depth is 1, the script will parse just the top email')

    def get_file_type(self, file_type):
        if not file_type:
            mime = magic.Magic()
            file_type = mime.from_file(self._file_path)
        if 'MIME entity text, ISO-8859 text' in file_type:
            file_type = 'application/pkcs7-mime'
        return file_type

    def check_if_is_msg(self):
        file_type_lower = self._file_type.lower()
        if 'composite document file v2 document' in file_type_lower \
                or 'cdfv2 microsoft outlook message' in file_type_lower:
            return True
        else:
            return False

    def parse(self):
        # we use the MAX_DEPTH_CONST to calculate the depth of the email
        # each level will reduce the max_depth by 1
        # not the best way to do it
        global MAX_DEPTH_CONST
        global USER_ENCODING
        global DEFAULT_ENCODING

        MAX_DEPTH_CONST = self._max_depth
        USER_ENCODING = self._forced_encoding
        DEFAULT_ENCODING = self._default_encoding

        try:
            file_type_lower = self._file_type.lower()
            if self._is_msg:
                email_data, attached_emails = handle_msg(self._file_path, self._file_name, self._parse_only_headers, self._max_depth)
                output = create_email_output(email_data, attached_emails)

            elif any(eml_candidate in file_type_lower for eml_candidate in
                     ['rfc 822 mail', 'smtp mail', 'multipart/signed', 'multipart/alternative', 'multipart/mixed', 'message/rfc822',
                      'application/pkcs7-mime', 'multipart/related', 'utf-8 (with bom) text']):
                if 'unicode (with bom) text' in file_type_lower or 'utf-8 (with bom) text' in file_type_lower:
                    self._bom = True
                email_data, attached_emails = handle_eml(
                    self._file_path, False, self._file_name, self._parse_only_headers, self._max_depth, bom=self._bom)
                output = create_email_output(email_data, attached_emails)

            elif ('ascii text' in file_type_lower or 'unicode text' in file_type_lower or
                  ('data' == file_type_lower.strip() and self._file_name and self._file_name.lower().strip().endswith('.eml'))):
                try:
                    # Try to open the email as-is
                    with open(self._file_path, 'r', encoding='utf-8') as f:
                        file_contents = f.read()

                    if file_contents and 'Content-Type:'.lower() in file_contents.lower():
                        email_data, attached_emails = handle_eml(self._file_path, b64=False, file_name=self._file_name,
                                                                 parse_only_headers=self._parse_only_headers, max_depth=self._max_depth)
                        output = create_email_output(email_data, attached_emails)
                    else:
                        # Try a base64 decode
                        b64decode(file_contents)
                        if file_contents and 'Content-Type:'.lower() in file_contents.lower():
                            email_data, attached_emails = handle_eml(self._file_path, b64=True, file_name=self._file_name,
                                                                     parse_only_headers=self._parse_only_headers,
                                                                     max_depth=self._max_depth)
                            output = create_email_output(email_data, attached_emails)
                        else:
                            try:
                                # Try to open
                                email_data, attached_emails = handle_eml(self._file_path, b64=False, file_name=self._file_name,
                                                                         parse_only_headers=self._parse_only_headers,
                                                                         max_depth=self._max_depth)
                                is_data_populated = is_email_data_populated(email_data)
                                if not is_data_populated:
                                    raise Exception("No email_data found")
                                output = create_email_output(email_data, attached_emails)
                            except Exception as e:
                                logging.debug("ParseEmailFiles failed with {}".format(str(e)))
                                raise Exception("Could not extract email from file. Possible reasons for this error are:\n"
                                                "- Base64 decode did not include rfc 822 strings.\n"
                                                "- Email contained no Content-Type and no data.")

                except Exception as e:
                    raise Exception("Exception while trying to decode email from within base64: {}\n\nTrace:\n{}"
                                    .format(str(e), traceback.format_exc()))
            else:

                raise Exception("Unknown file format: [{}] for file: [{}]".format(self._file_type, self._file_name))
            output = recursive_convert_to_unicode(output)
            self.parsed_email = output
            return output

        except Exception as ex:
            raise Exception(str(ex) + "\n\nTrace:\n" + traceback.format_exc())


def create_email_output(email_data, attached_emails):
    # for backward compatibility if there are no attached files we return single dict
    # if there are attached files then we will return array of all the emails
    res = []
    if email_data:
        res.append(email_data)
    if len(attached_emails) > 0:
        res.extend(attached_emails)
    if len(res) == 0:
        return None
    if len(res) == 1:
        return res[0]
    return res


def is_email_data_populated(email_data):
    # checks if email data has any item populated to it
    if email_data:
        for key, val in email_data.items():
            if val:
                return True
    return False


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
        if isinstance(replace_to_utf, str):
            return str(replace_to_utf, encoding='utf-8', errors='ignore')
        if not replace_to_utf:
            return replace_to_utf
        return replace_to_utf
    except TypeError:
        return replace_to_utf
