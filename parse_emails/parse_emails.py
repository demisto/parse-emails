import logging
import os
import subprocess
import traceback
from base64 import b64decode

import magic

from parse_emails.constants import KNOWN_MIME_TYPE, STRINGS_TO_REMOVE
from parse_emails.handle_eml import handle_eml, parse_inner_eml
from parse_emails.handle_msg import handle_msg

logger = logging.getLogger('parse_emails')


class EmailParser:
    """
    The core class for the EmailParser.
    """

    def __init__(self, file_path, max_depth=3, parse_only_headers=False, file_info='', forced_encoding=None,
                 default_encoding=None, file_name=None):

        self._file_path = file_path
        self._file_name = file_name or os.path.basename(self._file_path)
        self._file_type = self.get_file_type(file_info)
        self._max_depth = max_depth
        self._parse_only_headers = parse_only_headers
        self._forced_encoding = forced_encoding
        self._default_encoding = default_encoding
        self._is_msg = self.check_if_is_msg()
        logger.info(f'Parsing {file_path=}, {file_info=}, {self._file_name=}, {self._is_msg=}')
        self._bom = False
        self.parsed_email = None

        if self._max_depth < 1:
            raise Exception('Minimum max_depth is 1, the script will parse just the top email')

    def get_file_type(self, file_type):

        mime = magic.Magic(keep_going=True)
        if not file_type or not any(mime_type in file_type.lower() for mime_type in KNOWN_MIME_TYPE):
            file_type = mime.from_file(self._file_path)
            logger.info(f'file_type was empty, using {self._file_path=} to decide {file_type=}')

        if file_type == 'data' and self._file_name.lower().strip().endswith('.p7m'):
            logger.info(f'Removing signature from file {self._file_path}')
            remove_p7m_file_signature(self._file_path)
            file_type = mime.from_file(self._file_path)
            logger.info(f"Got file type '{file_type}' for file_path={self._file_path}")

        if 'MIME entity text, ISO-8859 text' in file_type or 'MIME entity, ISO-8859 text' in file_type:
            file_type = 'application/pkcs7-mime'

        logger.info(f'Returning {file_type=}')
        return file_type

    def check_if_is_msg(self):
        file_type_lower = self._file_type.lower()
        if 'composite document file v2 document' in file_type_lower \
                or 'cdfv2 microsoft outlook message' in file_type_lower:
            return True
        else:
            return False

    def parse(self):
        global USER_ENCODING
        global DEFAULT_ENCODING

        USER_ENCODING = self._forced_encoding
        DEFAULT_ENCODING = self._default_encoding

        try:
            file_type_lower = self._file_type.lower()
            logger.info(f'Parsing {file_type_lower=}')

            is_eml_ext = False
            if self._file_name and self._file_name.lower().strip().endswith('.eml'):
                is_eml_ext = True

            if self._is_msg:
                email_data, attached_emails, attached_eml = handle_msg(self._file_path, self._file_name,
                                                                       self._parse_only_headers,
                                                                       self._max_depth, original_depth=self._max_depth)
                if attached_eml:
                    attached_eml = parse_inner_eml(attachments=attached_eml, original_depth=self._max_depth)
                    attached_emails += attached_eml
                output = create_email_output(email_data, attached_emails)

            elif any(eml_candidate in file_type_lower for eml_candidate in
                     ['apple hfs', 'macintosh hfs', 'rfc 822 mail', 'smtp mail', 'multipart/signed',
                      'multipart/alternative', 'multipart/mixed',
                      'message/rfc822', 'application/pkcs7-mime', 'multipart/related', 'utf-8 (with bom) text']):
                if 'unicode (with bom) text' in file_type_lower or 'utf-8 (with bom) text' in file_type_lower:
                    self._bom = True
                email_data, attached_emails = handle_eml(
                    self._file_path, False, self._file_name, self._parse_only_headers, self._max_depth, bom=self._bom,
                    original_depth=self._max_depth)
                output = create_email_output(email_data, attached_emails)

            elif ('ascii text' in file_type_lower or 'unicode text' in file_type_lower or
                  ('data' == file_type_lower.strip() and is_eml_ext)):
                try:
                    # Try to open the email as-is
                    with open(self._file_path, encoding='utf-8', errors='replace') as f:
                        file_contents = f.read()

                    if (file_contents and 'Content-Type:'.lower() in file_contents.lower()) or (is_eml_ext and not
                                                                                                all(ord(char) < 128 for char in file_contents)):
                        email_data, attached_emails = handle_eml(self._file_path, b64=False, file_name=self._file_name,
                                                                 parse_only_headers=self._parse_only_headers,
                                                                 max_depth=self._max_depth, original_depth=self._max_depth)
                        output = create_email_output(email_data, attached_emails)
                    else:
                        # Try a base64 decode
                        b64decode(file_contents)
                        if file_contents and 'Content-Type:'.lower() in file_contents.lower():
                            email_data, attached_emails = handle_eml(self._file_path, b64=True, file_name=self._file_name,
                                                                     parse_only_headers=self._parse_only_headers,
                                                                     max_depth=self._max_depth, original_depth=self._max_depth)
                            output = create_email_output(email_data, attached_emails)
                        else:
                            try:
                                # Try to open
                                email_data, attached_emails = handle_eml(self._file_path, b64=False, file_name=self._file_name,
                                                                         parse_only_headers=self._parse_only_headers,
                                                                         max_depth=self._max_depth, original_depth=self._max_depth)
                                is_data_populated = is_email_data_populated(email_data)
                                if not is_data_populated:
                                    raise Exception("No email_data found")
                                output = create_email_output(email_data, attached_emails)
                            except Exception as e:
                                logger.debug(f"ParseEmailFiles failed with {str(e)}")
                                raise Exception("Could not extract email from file. Possible reasons for this error are:\n"
                                                "- Base64 decode did not include rfc 822 strings.\n"
                                                "- Email contained no Content-Type and no data.")

                except Exception as e:
                    raise Exception("Exception while trying to decode email from within base64: {}\n\nTrace:\n{}"
                                    .format(str(e), traceback.format_exc()))
            else:
                raise Exception(f"Unknown file format: [{self._file_type}] for file: [{self._file_name}]")

            outputs = recursive_convert_to_unicode(output)
            outputs = [remove_unicode_spaces(output) for output in outputs] if isinstance(outputs, list) else remove_unicode_spaces(outputs)
            self.parsed_email = outputs
            return outputs

        except Exception as ex:
            raise Exception(str(ex) + "\n\nTrace:\n" + traceback.format_exc())


def remove_unicode_spaces(output):
    for replace in STRINGS_TO_REMOVE:
        output = {key: val.replace(replace, '') if isinstance(val, str) else val for key,
                  val in output.items()} if isinstance(output, dict) else output.replace(replace, '')
    return output


def remove_p7m_file_signature(file_path):
    """
    Removes the signature from a p7m file.
    Run the command `openssl smime -verify <file_name.p7m> -noverify -inform DEM -out test.p7m` and creates the new file without the signature.
    """
    openssl_command = [
        'openssl', 'smime', '-verify', '-in', file_path, '-inform', 'DER', '-noverify', '-out', file_path
    ]

    try:
        # Execute the OpenSSL command
        logger.info(f"Run the openssl command: `{' '.join(openssl_command)}`")
        subprocess.run(openssl_command, check=True, capture_output=True)

    except Exception as e:
        raise Exception(f'Error occurred while removing {file_path} signature: {e}')


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
