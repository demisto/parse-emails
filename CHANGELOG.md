# Changelog

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
