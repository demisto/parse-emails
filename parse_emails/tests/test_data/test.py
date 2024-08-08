from parse_emails.parse_emails import EmailParser

email_parser = EmailParser('/Users/mmorag/dev/demisto/parse-emails/parse_emails/tests/test_data/chinese_email_test.eml')
after_parse = object.parse()
print(after_parse)
print(after_parse_2)
results = email_parser.parse()
expected_chinese_str = ('您好，'
    '这是一个示例邮件，用于演示指定的条件。'
    '它使用了 UTF-8 编码，可以支持多种语言的字符，包括中文。'
    '祝好，'
    '发件人'
)
assert results['Text'] == expected_chinese_str