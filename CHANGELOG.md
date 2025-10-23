# Changelog

v0.1.46
* Fixed an issue where encoded unknown-8bit characters in MSG files could not be parsed correctly.
  
v0.1.45
* Fixed an issue that caused the *From* header to be empty.

v0.1.44
* Fixed an issue where encoded unknown-8bit header in EML files could not be parsed correctly.

v0.1.43
* Added a fallback for UnicodeDecodeErrors when parsing attachments.

v0.1.42
* Fixed file-type resolution.

v0.1.41
* Removed redundant *demisto-sdk* dependency.

v0.1.40
* Added support for "MIME entity, with CRLF line terminators".

v0.1.39
* Infrastructure fixes.

v0.1.38
* Fixed an issue where EML files were not parsed if they had a corrupted EML file attached.

v0.1.37
* Fixed an issue where file_type was incorrectly detected as "AMUSIC Adlib Tracker".

v0.1.36
* Fixed an issue where file_type was incorrectly detected as "AMUSIC Adlib Tracker".

v0.1.35
* Fixed an issue where some EML files were incorrectly decoded.

v0.1.34
* Fixed an issue that prevented the headers from being parsed correctly for eml files (unknown-8bit encoding).
* Fixed an issue that email with attachment was parsed incorrectly for eml files.

v0.1.33
* Fixed an issue where html parts were not parsed properly in EML files.

v0.1.32
* Fixed an issue that prevented malformed email addresses from being parsed.

v0.1.31
* Fixed an issue that prevented the headers from being parsed correctly for MSG files (ASCII encoding).

v0.1.30
* Fixed an issue where email addresses with commas in the display name were not parsed correctly.

v0.1.28
* Fixed an issue where attachment file name encoded in windows-874 could not be parsed correctly.

v0.1.27
* Fixed an issue where UTF-8 encoded EML files with 8-bit *Content-Transfer-Encoding* headers could not be parsed correctly.

v0.1.23
* Fixed an issue where *Apple HFS* file type got "Unknown file format" while parsing.

v0.1.20
* Fixed an issue where EML multipart files were not parsed if they have a broken boundary.

v0.1.20
* fixed an issue when parsing msg with headers only.

v0.1.19
* Fixed an issue where the Bcc was not parsed.
* Fixed an issue where EML files were not parsed if they contained text at the beginning.

v0.1.18
* Fixed an issue where inline image did not parse.

v0.1.17
* Fixed an issue where several unicode spaces weren't parsed as expected.

v0.1.16
* Fixed an issue where *Macintosh HFS* file type got "Unknown file format" while parsing.

v0.1.16
* Fixed an issue where the email address fields were not extracted properly.

v0.1.15
* Fixed an issue where inline image without *Content-Disposition* header did not parse.

v0.1.14
* Fixed an issue where the parsed_email didn't contain the email wrapper and its AttachmentsData in cases of S/MIME files that lacked the To, From, and Subject fields.

v0.1.13
* Fixed an issue where an attachment file name with special characters was not decoded correctly.

v0.1.12
* Fixed an issue where a Subject containing special characters was not decoded correctly.

v0.1.11
* Deprecate the support for cid-embedded images in EML and MSG files.

v0.1.10
* Fixed an issue where the html in a msg will return as bytes and when doing the in search in *_embed_images_to_html_body* we get an error because we try to search a string in bytes.

v0.1.9
* Fixed an issue where an eml file containing non ascii characters was not decoded correctly.

v0.1.8
* Fixed an issue where an eml file containing chinese characters encoded with *iso-2022-jp*, *big5* and *gbk* was not decoded correctly.

v0.1.7
* Fixed an issue where an eml file containing chinese characters was not decoded correctly.

v0.1.6
* Fixed an issue where a multipart email was not parsed properly.
* Fixed an issue where parsing an msg file that contains an eml as an attachment failed.

v0.1.5
* Add outputs of Headers as a list of names and values.

v0.1.4
* Re-adding MIT License.

v0.1.3
* Infrastructure fixes.

v0.1.2
* Fix deploy step.

v0.1.1
* Fixed an issue where parsing numbers failed.

v0.1.0
* Changed packages manager from Pipenv to Poetry.

v0.0.16
* Fixed an issue where open files would fail on wrong encoding. Now ignoring failed characters.

v0.0.15
* Fixed an issue where the script failed on a particular MIME entity file type.

v0.0.14
* Fixed an issue where extracting the RTF body from msg emails failed.

v0.0.13
* Fixed an issue where signed .p7m files were not recognized.
* Added the option to pass in the filename.

v0.0.12
* Fixed an issue where attachment filename was not parsed properly.

v0.0.11
* Added support for cid-embedded images in EML files.

v0.0.10
* Fixed an issue where eml files that contained SMTP envelope headers where not handled properly.
* Fixed an issue where the script failed on particular MIME entity file type.

v0.0.9
* Fixed an issue where special characters in the text and html parts were not parsed properly.

v0.0.8
* Fixed an issue where the text body was not parsed properly.

v0.0.7
* Add support to extract RTF body from msg emails.

v0.0.6
* Fixed an issue where a long subject with special characters was not parsed properly.
