import email
import logging
from email.header import decode_header

logger = logging.getLogger('parse_emails')

ENCODINGS_TYPES = {'utf-8', 'iso8859-1'}


def convert_to_unicode(s, is_msg_header=True):
    # `is_msg_header` is retained for API compatibility with existing callers. It used to
    # gate a manual RFC 2047 decoding pass; decode_header below handles both cases.
    global ENCODINGS_TYPES  # noqa: F824
    try:
        res = ''  # utf encoded result
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
            try:
                s = str(email.header.make_header(email.header.decode_header(s)))
            except:  # noqa: E722
                logger.debug(f'unknown-8bit decoding failed for value: {s}')
        else:
            for file_data in ENCODINGS_TYPES:
                try:
                    s = s.decode(file_data).strip()
                    break
                except:  # noqa: E722
                    logger.debug(f'{file_data} decoding failed for value: {s}')
    return s
