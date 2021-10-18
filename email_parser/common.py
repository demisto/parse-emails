import base64
import logging
import quopri
import re
from email.header import decode_header

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
                logging.debug('Failed decoding mime-encoded string: {}. Will try regular decoding.'.format(str(e)))
        for decoded_s, encoding in decode_header(s):  # return a list of pairs(decoded, charset)
            if encoding:
                try:
                    res += str(decoded_s.decode(encoding).encode('utf-8'))
                except UnicodeDecodeError:
                    logging.debug('Failed to decode encoded_string')
                    replace_decoded = decoded_s.decode(encoding, errors='replace').encode('utf-8')
                    logging.debug('Decoded string with replace usage {}'.format(replace_decoded))
                    res += str(replace_decoded)
                ENCODINGS_TYPES.add(encoding)
            else:
                res += str(decoded_s)
        return res.strip()
    except Exception:
        for file_data in ENCODINGS_TYPES:
            try:
                s = s.decode(file_data).encode('utf-8').strip()
                break
            except:  # noqa: E722
                pass

    return s


def mime_decode(word_mime_encoded):
    prefix, charset, encoding, encoded_text, suffix = word_mime_encoded.groups()
    if encoding.lower() == 'b':
        byte_string = base64.b64decode(encoded_text)
    elif encoding.lower() == 'q':
        byte_string = quopri.decodestring(encoded_text)
    return prefix + byte_string.decode(charset) + suffix
