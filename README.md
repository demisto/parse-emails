# email-parser
Parse an email from an eml or msg file and populate all relevant context data to investigate the email. Also extracts inner attachments.

Getting Started
===============

Installation
************

Please install the latest email-parser version available from PyPI::

    $ pip3 install email-parser

The main class :class:`EmailParser` contains all what you need to parse te email.

    import email-parser

    email = EmailParser(file_path=test_path, max_depth=3, parse_only_headers=False, file_type=test_type, file_name=test_name)
    email.email_parser()

## Input

| **Argument Name** | **Description** |
| --- | --- |
| file_path | the file_path of a in msg or eml format |
| parse_only_headers | Will parse only the headers and return headers table |
| max_depth | How many levels deep we should parse the attached emails \(e.g. email contains an emails contains an email\). Default depth level is 3. Minimum level is 1, if set to 1 the script will parse only the first level email |
| file_type | the file info |
| file_name | the file name |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| To | This shows to whom the message was addressed, but may not contain the recipient's address. | string |
| CC | Email 'cc' addresses | string |
| From | This displays who the message is from, however, this can be easily forged and can be the least reliable. | string |
| Subject | Email subject | string |
| HTML | Email 'html' body if exists | string |
| Text | Email 'text' body if exists | string |
| Depth | The depth of the email. Depth=0 for the first level email. If email1 contains email2 contains email3. Then email1 depth is 0, email2 depth is 1, email3 depth is 2 | number |
| HeadersMap | The full email headers json | Unknown |
| HeadersMap.From | This displays who the message is from, however, this can be easily forged and can be the least reliable. | Unknown |
| HeadersMap.To | This shows to whom the message was addressed, but may not contain the recipient's address. | Unknown |
| HeadersMap.Subject | Email subject | String |
| HeadersMap.Date | The date and time the email message was composed | Unknown |
| HeadersMap.CC | Email 'cc' addresses | Unknown |
| HeadersMap.Reply-To | The email address for return mail | String |
| HeadersMap.Received | List of all the servers/computers through which the message traveled | String |
| HeadersMap.Message-ID | A unique string assigned by the mail system when the message is first created. These can easily be forged. \(e.g. 5c530c1b.1c69fb81.bd826.0eff@mx.google.com\) | String |
| AttachmentNames | The list of attachment names in the email | string |
| Format | The format of the email if available | string |

## Contributing
Contributions are welcome and appreciated. To contribute you can submit a PR. We suggest contancting us before submitting a PR to discuss your intentions and plans.

Before merging any PRs, we need all contributors to sign a contributor license agreement. By signing a contributor license agreement, we ensure that the community is free to use your contributions.

When you open a new pull request, a bot will evaluate whether you have signed the CLA. If required, the bot will comment on the pull request, including a link to accept the agreement. The CLA document is also available for review as a [PDF](https://github.com/demisto/content/blob/master/docs/cla.pdf).

If the `license/cla` status check remains on *Pending*, even though all contributors have accepted the CLA, you can recheck the CLA status by visiting the following link (replace **[PRID]** with the ID of your PR): https://cla-assistant.io/check/demisto/email-parser?pullRequest=[PRID] .
