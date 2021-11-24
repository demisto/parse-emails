[![Coverage Status](https://coveralls.io/repos/github/demisto/email-parser/badge.svg?branch=master)](https://coveralls.io/github/demisto/email-parser?branch=master)
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

The main class `EmailParser` contains all what you need to parse an email:

```python
import parse_emails

email = parse_emails.EmailParser(file_path=<file_path>, max_depth=3, parse_only_headers=False)
email.parse()
print(email.parsed_email['Subject'])
```

## Inputs

| **Argument Name** | **Description** |
| --- | --- |
| file_path* | the file_path of a in msg or eml format |
| parse_only_headers | Will parse only the headers and return headers table, Default is False|
| max_depth | How many levels deep we should parse the attached emails \(e.g. email contains an emails contains an email\). Default depth level is 3. Minimum level is 1, if set to 1 the script will parse only the first level email |
| file_info | the file info |

## Contributing
Contributions are welcome and appreciated. To contribute you can submit a PR.

Before merging any PRs, we need all contributors to sign a contributor license agreement. By signing a contributor license agreement, we ensure that the community is free to use your contributions.

When you open a new pull request, a bot will evaluate whether you have signed the CLA. If required, the bot will comment on the pull request, including a link to accept the agreement. The CLA document is also available for review as a [PDF](https://github.com/demisto/content/blob/master/docs/cla.pdf).

If the `license/cla` status check remains on *Pending*, even though all contributors have accepted the CLA, you can recheck the CLA status by visiting the following link (replace **[PRID]** with the ID of your PR): https://cla-assistant.io/check/demisto/email-parser?pullRequest=[PRID] .
