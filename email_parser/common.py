import base64
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
                print('Failed decoding mime-encoded string: {}. Will try regular decoding.'.format(str(e)))
        for decoded_s, encoding in decode_header(s):  # return a list of pairs(decoded, charset)
            if encoding:
                res += decoded_s.decode(encoding)
                ENCODINGS_TYPES.add(encoding)
            else:
                res += decoded_s.decode('utf-8', 'ignore')
        return res.strip()
    except Exception:
        for file_data in ENCODINGS_TYPES:
            try:
                s = s.decode(file_data).encode('utf-8').strip()
                break
            except:  # noqa: E722
                pass
    if isinstance(s, bytes):
        return s.decode('utf-8', 'ignore')
    return s


def mime_decode(word_mime_encoded):
    prefix, charset, encoding, encoded_text, suffix = word_mime_encoded.groups()
    if encoding.lower() == 'b':
        byte_string = base64.b64decode(encoded_text)
    elif encoding.lower() == 'q':
        byte_string = quopri.decodestring(encoded_text)
    return prefix + byte_string.decode(charset) + suffix
