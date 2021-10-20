[![Coverage Status](https://coveralls.io/repos/github/demisto/parse-emails/badge.svg?branch=master)](https://coveralls.io/github/demisto/parse-emails?branch=master)
[![CLA assistant](https://cla-assistant.io/readme/badge/demisto/parse-emails)](https://cla-assistant.io/demisto/parse-emails)
[![CircleCI](https://circleci.com/gh/demisto/parse-emails/tree/master.svg?style=svg)](https://circleci.com/gh/demisto/parse-emails/tree/master)
# parse-emails
Parses an email message file and extracts the data from it.

The key features are:
* Supports `.eml` and `.msg` files.
* Extracts nested attachments.

## Requirements

Python 3.8.5+

## Installation

```console
$ pip install parse-emails
```

## Usage

The main class `ParseEmails` contains all what you need to parse an email:

```python
import parse_emails

email = parse_emails.ParseEmails(file_path=<file_path>, max_depth=3, parse_only_headers=False)
email.parse_emails()
print(email.parsed_email['Subject'])
```

## Inputs

| **Argument Name** | **Description** |
| --- | --- |
| file_path* | the file_path of a in msg or eml format |
| parse_only_headers | Will parse only the headers and return headers table, Default is False|
| max_depth | How many levels deep we should parse the attached emails \(e.g. email contains an emails contains an email\). Default depth level is 3. Minimum level is 1, if set to 1 the script will parse only the first level email |
| file_info | the file info |

## Outputs
---

| **Path** | **Description** |
| --- | --- |
| To | This shows to whom the message was addressed, but may not contain the recipient's address.
| CC | Email 'cc' addresses |
| From | This displays who the message is from, however, this can be easily forged and can be the least reliable. |
| Subject | Email subject |
| HTML | Email 'html' body if exists |
| Text | Email 'text' body if exists |
| Depth | The depth of the email. Depth=0 for the first level email. If email1 contains email2 contains email3. Then email1 depth is 0, email2 depth is 1, email3 depth is 2 |
| HeadersMap | The full email headers json |
| HeadersMap.From | This displays who the message is from, however, this can be easily forged and can be the least reliable. |
| HeadersMap.To | This shows to whom the message was addressed, but may not contain the recipient's address. |
| HeadersMap.Subject | Email subject |
| HeadersMap.Date | The date and time the email message was composed |
| HeadersMap.CC | Email 'cc' addresses |
| HeadersMap.Reply-To | The email address for return mail |
| HeadersMap.Received | List of all the servers/computers through which the message traveled |
| HeadersMap.Message-ID | A unique string assigned by the mail system when the message is first created. These can easily be forged. \(e.g. 5c530c1b.1c69fb81.bd826.0eff@mx.google.com\) |
| AttachmentNames | The list of attachment names in the email |
| Format | The format of the email if available |

## Contributing
Contributions are welcome and appreciated. To contribute you can submit a PR. We suggest contancting us before submitting a PR to discuss your intentions and plans.

Before merging any PRs, we need all contributors to sign a contributor license agreement. By signing a contributor license agreement, we ensure that the community is free to use your contributions.

When you open a new pull request, a bot will evaluate whether you have signed the CLA. If required, the bot will comment on the pull request, including a link to accept the agreement. The CLA document is also available for review as a [PDF](https://github.com/demisto/content/blob/master/docs/cla.pdf).

If the `license/cla` status check remains on *Pending*, even though all contributors have accepted the CLA, you can recheck the CLA status by visiting the following link (replace **[PRID]** with the ID of your PR): https://cla-assistant.io/check/demisto/email-parser?pullRequest=[PRID] .
