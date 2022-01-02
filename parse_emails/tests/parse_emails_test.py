# coding=utf-8
from __future__ import print_function

import pytest

from parse_emails.handle_eml import unfold
from parse_emails.handle_msg import (DataModel, MsOxMessage,
                                     create_headers_map, get_msg_mail_format,
                                     handle_msg)
from parse_emails.parse_emails import EmailParser


def test_parse():
    test_path = 'parse_emails/tests/test_data/eml_contains_base64_eml.eml'

    email_parser = EmailParser(file_path=test_path)
    results = email_parser.parse()
    assert len(results) == 2
    assert results[0]['Subject'] == 'Fwd: test - inner attachment eml (base64)'


def test_msg_html_with_attachments():
    msg = MsOxMessage('parse_emails/tests/test_data/html_attachment.msg')
    assert msg is not None
    msg_dict = msg.as_dict(max_depth=2)
    assert 'This is an html email' in msg_dict['Text']
    attachments_list = msg.get_all_attachments()
    assert len(attachments_list) == 1
    attach = attachments_list[0]
    assert attach.AttachFilename == 'dummy-attachment.txt'
    assert attach.AttachMimeTag == 'text/plain'
    assert attach.data == b'This is a text attachment'


def test_msg_utf_encoded_subject():
    msg = MsOxMessage('parse_emails/tests/test_data/utf_subject.msg')
    assert msg is not None
    msg_dict = msg.as_dict(max_depth=2)
    # we test that subject which has utf-8 encoding (in the middle) is actually decoded
    assert '?utf-8' in msg_dict['HeadersMap']['Subject']
    subj = msg_dict['Subject']
    assert 'TESTING' in subj and '?utf-8' not in subj


def test_msg_with_attachments():
    test_path = 'parse_emails/tests/test_data/html_attachment.msg'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['Attachments'] == 'dummy-attachment.txt'


def test_eml_smtp_type():
    test_path = 'parse_emails/tests/test_data/smtp_email_type.eml'
    test_type = 'SMTP mail, UTF-8 Unicode text, with CRLF terminators'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['Subject'] == 'Test Smtp Email'


# this is a test for another version of a multipart signed eml file
def test_smime2():

    test_path = 'parse_emails/tests/test_data/smime2.p7m'
    test_type = 'multipart/signed; protocol="application/pkcs7-signature";, ASCII text, with CRLF line terminators'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['Subject'] == 'Testing signed multipart email'


def test_eml_contains_eml():
    test_path = 'parse_emails/tests/test_data/Fwd_test-inner_attachment_eml.eml'
    test_type = 'news or mail text, ASCII text'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert len(results.parsed_email) == 2
    assert results.parsed_email[0]['Subject'] == 'Fwd: test - inner attachment eml'
    assert 'ArcSight_ESM_fixes.yml' in results.parsed_email[0]['Attachments']
    assert 'test - inner attachment eml.eml' in results.parsed_email[0]['Attachments']
    assert results.parsed_email[0]['Depth'] == 0
    assert results.parsed_email[1]["Subject"] == 'test - inner attachment eml'
    assert 'CS Training 2019 - EWS.pptx' in results.parsed_email[1]["Attachments"]
    assert results.parsed_email[1]['Depth'] == 1


def test_eml_contains_msg():
    test_path = 'parse_emails/tests/test_data/DONT_OPEN-MALICIOUS.eml'
    test_type = 'news or mail text, ASCII text'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()
    assert len(results.parsed_email) == 2
    assert results.parsed_email[0]['Subject'] == 'DONT OPEN - MALICIOS'
    assert results.parsed_email[0]['Depth'] == 0

    assert 'Attacker+email+.msg' in results.parsed_email[0]['Attachments']
    assert results.parsed_email[1]["Subject"] == 'Attacker email'
    assert results.parsed_email[1]['Depth'] == 1


def test_eml_contains_eml_depth():

    test_path = 'parse_emails/tests/test_data/Fwd_test-inner_attachment_eml.eml'
    test_type = 'news or mail text, ASCII text'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert len(results.parsed_email) == 2
    assert results.parsed_email[0]['Subject'] == 'Fwd: test - inner attachment eml'
    assert 'ArcSight_ESM_fixes.yml' in results.parsed_email[0]['Attachments']
    assert 'test - inner attachment eml.eml' in results.parsed_email[0]['Attachments']
    assert results.parsed_email[0]['Depth'] == 0


def test_eml_utf_text():

    test_path = 'parse_emails/tests/test_data/utf_8_email.eml'
    test_type = 'UTF-8 Unicode text, with very long lines, with CRLF line terminators'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['Subject'] == 'Test UTF Email'


def test_eml_utf_text_with_bom():
    '''Scenario: Parse an eml file that is UTF-8 Unicode (with BOM) text

    Given
    - A UTF-8 encoded eml file with BOM

    When
    - Executing ParseEmailFiles automation on the uploaded eml file

    Then
    - Ensure eml email file is properly parsed
    '''

    test_path = 'parse_emails/tests/test_data/utf_8_with_bom.eml'
    test_type = 'RFC 822 mail text, UTF-8 Unicode (with BOM) text, with very long lines, with CRLF line terminators'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['Subject'] == 'Test UTF Email'


def test_email_with_special_character():

    test_path = 'parse_emails/tests/test_data/email_with_special_char_bytes.eml'
    test_type = 'RFC 822 mail text, ISO-8859 text, with very long lines, with CRLF line terminators'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()
    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['Subject'] == 'Hello dear friend'


def test_unfold():
    assert unfold('test\n\tthis') == 'test this'
    assert unfold('test\r\n\tthis') == 'test this'
    assert unfold('test   \r\n this') == 'test this'


def test_email_raw_headers():
    test_path = 'parse_emails/tests/test_data/multiple_to_cc.eml'
    test_type = 'SMTP mail, UTF-8 Unicode text, with CRLF terminators'

    results = EmailParser(file_path=test_path, max_depth=1, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['From'] == 'test@test.com'
    assert results.parsed_email['To'] == 'test@test.com, example1@example.com'
    assert results.parsed_email['CC'] == 'test@test.com, example1@example.com'
    assert results.parsed_email['HeadersMap']['From'] == 'Guy Test <test@test.com>'
    assert results.parsed_email['HeadersMap']['To'] == 'Guy Test <test@test.com>, Guy Test1 <example1@example.com>'
    assert results.parsed_email['HeadersMap']['CC'] == 'Guy Test <test@test.com>, Guy Test1 <example1@example.com>'


def test_email_raw_headers_from_is_cyrillic_characters():
    """
    Given:
     - The email message the should pe parsed.
     - Checking an email file that contains '\r\n' in it's 'From' header.

    When:
     - After parsed email file into Email object

    Then:
     - Validate that all raw headers are valid.
    """
    test_path = 'parse_emails/tests/test_data/multiple_to_cc_from_Cyrillic_characters.eml'
    test_type = 'SMTP mail, UTF-8 Unicode text, with CRLF terminators'

    results = EmailParser(file_path=test_path, max_depth=1, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['From'] == 'no-reply@google.com'
    assert results.parsed_email['To'] == 'test@test.com, example1@example.com'
    assert results.parsed_email['CC'] == 'test@test.com, example1@example.com'
    assert results.parsed_email['HeadersMap']['From'] == u'"✅✅✅ ВА ! https://example.com  ." <no-reply@google.com>'
    assert results.parsed_email['HeadersMap']['To'] == 'Guy Test <test@test.com>, Guy Test1 <example1@example.com>'
    assert results.parsed_email['HeadersMap']['CC'] == 'Guy Test <test@test.com>, Guy Test1 <example1@example.com>'


def test_eml_contains_eml_with_status():
    subject_attach = '=?iso-8859-7?B?Rlc6IEZPT0RMSU5LINDLx9HZzMc=?='  # disable-secrets-detection

    test_path = 'parse_emails/tests/test_data/ParseEmailFiles-test-emls.eml'
    test_type = 'SMTP mail, UTF-8 Unicode text, with CRLF terminators'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert results.parsed_email[1]['Subject'] == subject_attach


@pytest.mark.parametrize('file_name', ['eml_contains_base64_eml.eml', 'eml_contains_base64_eml2.eml'])
def test_eml_contains_base64_encoded_eml(file_name):
    test_path = f'parse_emails/tests/test_data/{file_name}'
    test_type = 'SMTP mail, UTF-8 Unicode text, with CRLF terminators'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert len(results.parsed_email) == 2
    assert results.parsed_email[0]['Subject'] == 'Fwd: test - inner attachment eml (base64)'
    assert 'message.eml' in results.parsed_email[0]['Attachments']
    assert results.parsed_email[0]['Depth'] == 0

    assert results.parsed_email[1]["Subject"] == 'test - inner attachment eml'
    assert results.parsed_email[1]['Depth'] == 1


# check that we parse an email with "data" type and eml extension
@pytest.mark.parametrize('file_info', ['data', 'data\n'])
def test_eml_data_type(file_info):
    test_path = 'parse_emails/tests/test_data/smtp_email_type.eml'
    test_type = file_info

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()
    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['Subject'] == 'Test Smtp Email'


def test_smime():
    test_path = 'parse_emails/tests/test_data/smime.p7m'
    test_type = 'multipart/signed; protocol="application/pkcs7-signature";, ASCII text, with CRLF line terminators'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['Subject'] == 'Testing Email Attachment'


def test_smime_msg():
    test_path = 'parse_emails/tests/test_data/smime-p7s.msg'
    test_type = 'CDFV2 Microsoft Outlook Message'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['Subject'] == 'test'


def test_msg_headers_map():
    email_data, ignore = handle_msg('parse_emails/tests/test_data/utf_subject.msg', 'utf_subject.msg')
    assert '?utf-8' not in email_data['Subject']
    assert 'TESTING' in email_data['Subject']
    assert 'This is a test email.' in email_data['Text']
    assert 'mobi777@gmail.com' in email_data['From']
    assert 47 == len(email_data['HeadersMap'])
    assert isinstance(email_data['HeadersMap']['Received'], list)
    assert 8 == len(email_data['HeadersMap']['Received'])
    assert '1;DM6PR11MB2810;31:tCNnPn/K8BROQtLwu3Qs1Fz2TjDW+b7RiyfdRvmvCG+dGRQ08+3CN4i8QpLn2o4' \
           in email_data['HeadersMap']['X-Microsoft-Exchange-Diagnostics'][2]
    assert '2eWTrUmQCI=;20:7yMOvCHfrNUNaJIus4SbwkpcSids8EscckQZzX/oGEwux6FJcH42uCQd9tNH8gmDkvPw' \
           in email_data['HeadersMap']['X-Microsoft-Exchange-Diagnostics'][2]
    assert 'text/plain' in email_data['Format']


def test_unknown_file_info():
    test_path = 'parse_emails/tests/test_data/smtp_email_type.eml'
    test_type = 'bad'

    try:
        results = EmailParser(file_path=test_path, max_depth=1, parse_only_headers=False, file_info=test_type)
        results.parse()
    except Exception as e:
        gotexception = True
        results = e

    assert gotexception
    assert 'Unknown file format:' in str(results)
    assert 'smtp_email_type.eml' in str(results)


def test_no_content_type_file():
    test_path = 'parse_emails/tests/test_data/no_content_type.eml'
    test_type = 'ascii text'

    results = EmailParser(file_path=test_path, max_depth=1, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['Subject'] == 'No content type'


def test_get_msg_mail_format():
    msg_mail_format = get_msg_mail_format({
        'Headers': 'Content-type:text/plain;'
    })
    assert msg_mail_format == 'text/plain'

    msg_mail_format = get_msg_mail_format({
        'Something': 'else'
    })
    assert msg_mail_format == ''

    msg_mail_format = get_msg_mail_format({
        'Headers': None
    })
    assert msg_mail_format == ''


def test_no_content_file():
    test_path = 'parse_emails/tests/test_data/no_content.eml'
    test_type = 'ascii text'

    try:
        results = EmailParser(file_path=test_path, max_depth=1, parse_only_headers=False, file_info=test_type)
        results.parse()
    except Exception as e:
        gotexception = True
        results = e
    assert gotexception
    assert 'Could not extract email from file' in str(results)


def test_eml_contains_htm_attachment():
    test_path = 'parse_emails/tests/test_data/eml_contains_htm_attachment.eml'
    test_type = 'SMTP mail, UTF-8 Unicode text, with CRLF terminators'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email[u'Attachments'] == '1.htm'


def test_signed_attachment():
    test_path = 'parse_emails/tests/test_data/email_with_signed_attachment.eml'
    test_type = 'multipart/mixed'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert len(results.parsed_email) == 2


def test_eml_format_multipart_mix():
    test_path = 'parse_emails/tests/test_data/multipart_mixed_format.p7m'
    test_type = 'multipart/mixed'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert "Warsaw, Poland <o:p></o:p>" in results.parsed_email['HTML']


def test_eml_format_multipart_related():
    test_path = 'parse_emails/tests/test_data/multipart_related_format.p7m'
    test_type = 'multipart/related'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert "Warsaw, Poland <o:p></o:p>" in results.parsed_email['HTML']


def test_eml_base64_header_comment_although_string():
    test_path = 'parse_emails/tests/test_data/DONT_OPEN-MALICIOUS_base64_headers.eml'
    test_type = 'UTF-8 Unicode text, with very long lines, with CRLF line terminators'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert len(results.parsed_email) == 2
    assert results.parsed_email[0]['Subject'] == 'DONT OPEN - MALICIOS'
    assert results.parsed_email[0]['Depth'] == 0

    assert 'Attacker+email+.msg' in results.parsed_email[0]['Attachments']
    assert results.parsed_email[1]["Subject"] == 'Attacker email'
    assert results.parsed_email[1]['Depth'] == 1


def test_message_rfc822_without_info():
    """
    Given:
     - EML file with content type message/rfc822
     - Demisto entry metadata returned without info, but with type

    When:
     - Running the script on the email file

    Then:
     - Verify the script runs successfully
     - Ensure 2 entries are returned as expected
    """
    test_path = 'parse_emails/tests/test_data/eml_contains_base64_eml2.eml'
    test_type = 'message/rfc822'

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert len(results.parsed_email) == 2
    assert results.parsed_email[0]['To'] == 'wowo@demisto.com'
    assert results.parsed_email[1]['To'] == 'soso@demisto.com'


def test_create_headers_map_empty_headers():
    """
    Given:
     - The input headers is None.

    When:
     - Running the create_headers_map command on these  headers.

    Then:
     - Validate that the function does not fail
    """
    msg_dict = {
        'From': None, 'CC': None, 'BCC': None, 'To': u'test@demisto.com', 'Depth': 0, 'HeadersMap': {},
        'Attachments': u'image002.png,image003.png,image004.png,image001.png', 'Headers': None, 'Text': u'Hi',
        'Subject': u'test'
    }
    headers, headers_map = create_headers_map(msg_dict.get('Headers'))
    assert headers == []
    assert headers_map == {}


def test_eml_contains_htm_attachment_empty_file():
    """
    Given: An email containing both an empty text file and a base64 encoded htm file.
    When: Parsing a valid email file with default parameters.
    Then: Three entries will be returned to the war room. One containing the command results. Another
          containing the empty file. The last contains the htm file.
    """
    test_path = 'parse_emails/tests/test_data/eml_contains_emptytxt_htm_file.eml'
    test_type = "RFC 822 mail text, with CRLF line terminators"

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert len(results.parsed_email) == 2
    assert results.parsed_email[0]['AttachmentNames'] == ['unknown_file_name0', 'SomeTest.HTM']


def test_eml_contains_htm_attachment_empty_file_max_depth():
    """
    Given: An email containing both an empty text file and a base64 encoded htm file.
    When: Parsing a valid email file with max_depth=1.
    Then: One entry containing the command results will be returned to the war room.
    """
    test_path = 'parse_emails/tests/test_data/eml_contains_emptytxt_htm_file.eml'
    test_type = "RFC 822 mail text, with CRLF line terminators"

    results = EmailParser(file_path=test_path, max_depth=1, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)


def test_only_parts_of_object_email_saved():
    """

    Fixes: https://github.com/demisto/etc/issues/29476
    Given:
        an eml file with a line break (`\n`) in the payload that has failed due to wring type.
    Then:
        filter only parts that are of type email.message.Message.

    """
    test_path = 'parse_emails/tests/test_data/new-line-in-parts.eml'
    test_type = "RFC 822 mail text, with CRLF line terminators"

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['AttachmentNames'] == ['logo5.png', 'logo2.png']


def test_pkcs7_mime():
    """
    Given: An email file smime2.p7m of type application/pkcs7-mime and info -
    MIME entity text, ISO-8859 text, with very long lines, with CRLF line terminators
    When: Parsing the email.
    Then: The email is parsed correctly.
    """
    test_path = 'parse_emails/tests/test_data/smime2.p7m'
    test_type = "MIME entity text, ISO-8859 text, with very long lines, with CRLF line terminators"

    results = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
    results.parse()

    assert isinstance(results.parsed_email, dict)
    assert results.parsed_email['Subject'] == 'Testing signed multipart email'


def test_PtypString():
    data_value = DataModel.PtypString(b'IPM.Note')
    assert data_value == u'IPM.Note'

    data_value = DataModel.PtypString(b'I\x00P\x00M\x00.\x00N\x00o\x00t\x00e\x00')
    assert data_value == u'IPM.Note'

    data_value = DataModel.PtypString(b'e\x9c\xe6\xb9pe')
    assert data_value == u'eśćąpe'


def test_parse_body_with_russian_language():
    email_data, ignore = handle_msg('parse_emails/tests/test_data/Phishing_TEST.msg', 'Phishing_TEST.msg')
    assert str(email_data['Text']).startswith('Уважаемые коллеги')
    assert 'Уважаемые' in email_data['HTML']


# def test_eml_contains_html_and_text():
#     test_path = 'parse_emails/tests/test_data/multipart_alternative_format.p7m'
#     test_type = 'multipart/alternative;, ISO-8859 text, with CRLF line terminators'
#
#     results = ParseEmails(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
#     results.parse_emails()
#
#     assert isinstance(results.parsed_email, dict)
#     assert "<p class=\"MsoNormal\"><span style='font-size:10.0pt;font-family:" \
#            "\"xxxxx\",sans-serif;color:black'>żółć<o:p></o:p>" in results.parsed_email['HTML']


# def test_double_dots_removed():
#     """
#     Fixes: https://github.com/demisto/etc/issues/27229
#     Given:
#         an eml file with a line break (`=\r\n`) which caused the duplication of dots (`..`).
#     Then:
#         replace the two dots with one and test that `part.get_payload()` decodes it correctly.
#     """
#     test_path = 'parse_emails/tests/test_data/multiple_to_cc.eml'
#     test_type = "RFC 822 mail text, with CRLF line terminators"
#
#     results = ParseEmails(file_path=test_path, max_depth=1, parse_only_headers=False, file_info=test_type)
#     results.parse_emails()
#     print(results.parsed_email['HTML'])
#
#     assert 'http://schemas.microsoft.com/office/2004/12/omml' in results.parsed_email['HTML']


# def test_rtf_msg():
#     test_path = 'parse_emails/tests/test_data/msg_with_rtf_compressed.msg'
#     test_type = 'CDFV2 Microsoft Outlook Message'
#
#     results = ParseEmails(file_path=test_path, max_depth=3, parse_only_headers=False, file_info=test_type)
#     results.parse_emails()
#
#     assert '<html xmlns:v="urn:schemas-microsoft-com:vml"' in results[0]['EntryContext']['Email']['HTML']
#     assert 'src="data:image/png;base64, '
