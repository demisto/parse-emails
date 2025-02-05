import base64
import email
import logging
import quopri
import re
from email.header import decode_header

logger = logging.getLogger('parse_emails')

MIME_ENCODED_WORD = re.compile(r'(.*)=\?(.+)\?([B|Q])\?(.+)\?=(.*)')  # guardrails-disable-line
ENCODINGS_TYPES = {'utf-8', 'iso8859-1'}


def convert_to_unicode(s, is_msg_header=True):
    global ENCODINGS_TYPES
    try:
        res = ''  # utf encoded result
        if is_msg_header:  # Mime encoded words used on message headers only
            try:
                word_mime_encoded = s and MIME_ENCODED_WORD.search(s)
                if word_mime_encoded:
                    word_mime_decoded = mime_decode(word_mime_encoded)
                    if word_mime_decoded and not MIME_ENCODED_WORD.search(word_mime_decoded):
                        # ensure decoding was successful
                        return word_mime_decoded
            except Exception as e:
                # in case we failed to mine-decode, we continue and try to decode
                logger.debug(f'Failed decoding mime-encoded string: {str(e)}. Will try regular decoding.')
        for decoded_s, encoding in decode_header(s):  # return a list of pairs(decoded, charset)
            if encoding:
                try:
                    res += decoded_s.decode(encoding)
                except UnicodeDecodeError:
                    logger.debug('Failed to decode encoded_string')
                    replace_decoded = decoded_s.decode(encoding, errors='replace')
                    logger.debug(f'Decoded string with replace usage {replace_decoded}')
                    res += replace_decoded
                ENCODINGS_TYPES.add(encoding)
            else:
                if isinstance(decoded_s, str):
                    res += decoded_s
                else:
                    res += str(decoded_s, 'utf-8')
        return res.strip()
    except Exception:
        if s and 'unknown-8bit' in s:
            s = str(email.header.make_header(email.header.decode_header(s)))
        else:
            for file_data in ENCODINGS_TYPES:
                try:
                    s = s.decode(file_data).strip()
                    break
                except:  # noqa: E722
                    pass
    return s


def mime_decode(word_mime_encoded):
    prefix, charset, encoding, encoded_text, suffix = word_mime_encoded.groups()
    if encoding.lower() == 'b':
        byte_string = base64.b64decode(encoded_text)
    elif encoding.lower() == 'q':
        byte_string = quopri.decodestring(encoded_text, header=True)
    return prefix + byte_string.decode(charset) + suffix
