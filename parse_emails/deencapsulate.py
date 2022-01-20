#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of RTFDE, a RTF De-Encapsulator.
# Copyright © 2020 seamus tuohy, <code@seamustuohy.com>
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the included LICENSE file for details.

import re
from lark import Lark
from lark.tree import Tree
from lark.lexer import Token

from RTFDE.transformers import RTFUnicodeDecoder, StripNonVisibleRTFGroups, RTFCleaner

# For catching exceptions
from RTFDE.exceptions import NotEncapsulatedRtf, MalformedEncapsulatedRtf, MalformedRtf
from io import BufferedReader


import logging
log = logging.getLogger('RTFDE')


class DeEncapsulator():
    """De-Encapsulating RTF converter of HTML/TEXT found in .msg files.

    De-encapsulation enables previously encapsulated HTML and plain text content to be extracted and rendered as HTML and plain text instead of the encapsulating RTF content. After de-encapsulation, the HTML and plain text should differ only minimally from the original HTML or plain text content.


        Parameters:
            raw_rtf: (str): It's the raw RTF string.

            grammar: (raw str): OPTIONAL - Lark (https://github.com/lark-parser/lark) parsing grammar which defines the RTF language. If you think my grammar is shoddy this is your chance to test out a better one and make a pull request. :D
    """

    def __init__(self, raw_rtf: str, grammar: str = None):
        """Load in the Encapsulated test and setup the grammar used to parse the encapsulated RTF.

        NOTE: This does not do the parsing in the init so that you can initiate the object and do the parsing step by step.


        Parameters:
            raw_rtf: (str): It's the raw RTF string.

            grammar: (raw str): OPTIONAL - Lark (https://github.com/lark-parser/lark) parsing grammar which defines the RTF language. If you think my grammar is shoddy this is your chance to test out a better one and make a pull request. :D

        """
        self.content = None
        self.content_type = None
        self._content_type_token = None
        self.html = None
        self.plain_text = None
        self.stripped_rtf = None
        self.simplified_rtf = None
        self.full_tree = None
        self.doc_tree = None
        self.charset = None
        self.text_codec = None
        self._catch_common_validation_issues(raw_rtf)
        if isinstance(raw_rtf, bytes):
            self.raw_rtf = raw_rtf.decode()
        elif isinstance(raw_rtf, str):
            self.raw_rtf = raw_rtf
        else:
            raise TypeError("DeEncapssulator only accepts RTF files in string or byte-string formats")
        if grammar is not None:
            self._grammar = grammar
        else:
            self._grammar = r"""
start : OPENPAREN document CLOSEPAREN

document: (CONTROLWORD | CONTROLSYMBOL | TEXT | group | " " | RTFESCAPE)+
group: OPENPAREN (CONTROLWORD | CONTROLSYMBOL | TEXT | group | RTFESCAPE)* CLOSEPAREN

// Text is given priority over control terms with TERM.PRIORITY = 2
// This is used to ensure that escaped \ AND { AND } are not matched in others
TEXT.2: /\\\\/ | /\\[{}]/+ | /[^\\{}]/+
CONTROLWORD: /(?<!\\)\\/ /[a-zA-Z]/+ /[0-9\-]/*
CONTROLSYMBOL: /(?<!\\)\\/ "|" | "~" | "-" | "_" | ":" | "\*" | "\\{" | "\\}"

// Increased priority of escape chars to make unescaping easier
// Multiple char acceptance is important here because if you just catch one escape at a time you mess up multi-byte values.
RTFESCAPE.3: ("\\'" /[0-9A-Fa-f]/~2)+ | ("\\u" /[-]*[0-9]+\s?\??/)+

OPENPAREN:  "{"
CLOSEPAREN: "}"

%import common.ESCAPED_STRING
%import common.SIGNED_NUMBER

%import common.WS
%ignore WS
"""
    @staticmethod
    def _catch_common_validation_issues(raw_rtf):
        """Checks for likely common valid input mistakes that may occur when folks try to use this library and raises exceptions to try and help identify them."""
        if isinstance(raw_rtf, BufferedReader):
            raise TypeError("Data passed as file pointer. DeEncapsulator only accepts strings and byte-strings.")
        if raw_rtf == None:
            raise TypeError("Data passed as raw RTF file is a null object `None` keyword.")
        if raw_rtf[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            raise TypeError("Data passed is a full MSG object. You must extract the encapsulated RTF body first.")
        if (raw_rtf == b"") or (raw_rtf == ""):
            raise MalformedRtf("Data passed as raw RTF file is an empty string.")

    def _simplify_text_for_parsing(self):
        """Replaces control chars within the text with their RTF encoded versions \\'HH.
        """
        cleaned = self.stripped_rtf.replace('\\\\', "\\'5c")
        cleaned = cleaned.replace('\\{', "\\'7b")
        cleaned = cleaned.replace('\\}', "\\'7d")
        return cleaned

    def deencapsulate(self):
        """De-encapsulate the RTF content loaded into the De-Encapsulator.

        Once you have loaded in the raw rtf this function will set the properties containing the encapsulated content. The `content` property will store the content no matter what format it is in. The `html` and `text` properties will be populated based on the type of content that is extracted. (self.html will be populated if it is html and self.text if it is plain text.)
        """
        self.stripped_rtf = self._strip_htmlrtf_sections()
        self.simplified_rtf = self._simplify_text_for_parsing()
        self.doc_tree = self._parse_rtf()
        self._validate_encapsulation()
        self.charset = self._get_charset()
        self.content = self._deencapsulate_from_tree()
        self.content_type = self.get_content_type()
        if self.content_type == 'html':
            self.html = self.content
        else:
            self.text = self.content

    def get_content_type(self):
        """Provide the type of content encapsulated in RTF.

        NOTE: This function will only work after the header validation has completed. Header validation also extracts the content type of the encapsulated data.
        """
        if self._content_type_token is None:
            self._validate_FROM_in_doc_header()
        elif self._content_type_token == '\\fromhtml1':
            return 'html'
        elif self._content_type_token == '\\fromtext':
            return "text"
        else:
            raise NotEncapsulatedRtf("Data is missing encapsulated content type header (the FROM header).")

    def _validate_encapsulation(self):
        """Runs simple tests to validate that the file in question is an rtf document which contains encapsulation.
        """
        self._validate_rtf_doc_header()
        self._validate_FROM_in_doc_header()

    def _parse_rtf(self) -> Tree:
        """Parse RTF file's header and document and extract the objects within the RTF into a Tree."""
        parser = Lark(self._grammar, parser='lalr')
        self.full_tree = parser.parse(self.simplified_rtf)
        # An RTF file has the following syntax: '{' <header & document>'}'
        # We only need the header and document so we only extract the 1st obj.
        return self.full_tree.children[1]

    def _strip_htmlrtf_sections(self) -> Tree:
        """Strip out \\htmlrtf tagged sections which need to be ignored in the de-encapsulation and are difficult to extract after it has been converted into a tree.

        The \\htmlrtf keyword toggles pieces of RTF to be ignored during reverse RTF->HTML conversion. Lack of a parameter turns it on, parameter 0 turns it off. But, these are not always included in a consistent way. They can appear withing and across groups in the stream. So, they need to be extracted before the stream is tokenized and placed into a tree.
        """
        htmlrtf = re.compile(r'[\s]*\\htmlrtf[^0].*?\\htmlrtf0[\n]*', flags=re.MULTILINE|re.DOTALL)
        return  htmlrtf.sub("", self.raw_rtf)

    def _deencapsulate_from_tree(self) -> str:
        """De-encapsulates HTML from document tree into final content.
        """
        decoded_tree = RTFUnicodeDecoder().visit_topdown(self.doc_tree)

        stripper = StripNonVisibleRTFGroups()
        stripped_tree = stripper.transform(decoded_tree)

        cleaner = RTFCleaner(rtf_codec=self.text_codec)
        cleaned_text = cleaner.transform(stripped_tree)
        # The conversion process inserts spaces on newlines where there were none
        cleaned_text = re.sub(r'[\r\n][\s\r\n]{2,}', '\n', cleaned_text)
        return cleaned_text

    def _get_header_control_words_before_first_group(self) -> list:
        """Extracts all the control words in the first 20 tokens of the document or all the tokens which occur before the first group (whichever comes first.)

        This is used to extract initial header values for validation functions.
        """
        initial_control_words = []
        for token in self.doc_tree.children[:20]:
            if isinstance(token, Token):
                initial_control_words.append(token)
            else:
                return initial_control_words
        return initial_control_words

    def _get_charset(self, fallback_to_default:bool =False) -> str:
        """Extracts the RTF charset keyword from the RTF streams header.

        Parameters:
            fallback_to_default (bool): Allows you to force the use of the default charset "\ansi" if one is not found.
        """
        main_headers = self._get_header_control_words_before_first_group()
        charset = None
        for token in main_headers:
            if token in ["\\ansi", "\\mac", "\\pc", "\\pac"]:
                return token

        if charset is None:
            log.debug("Acceptable charset not found as the second token in the RTF stream. The control word for the character set must precede any plain text or any table control words. So, if this stream doesn't have one it is malformed or corrupted.")
            if fallback_to_default is False:
                raise MalformedRtf("RTF stream does not include charset control word.")
            else:
                log.warning("The fallback_to_default option on _get_charset is considered DANGEROUS if used on possibly malicious samples. Make sure you know what you are doing before using it.")
                log.info("Attempting to decode RTF using the defulat charset ansi. This is not recommended and could have unforeseen consequences for the resulting file and your systems security.")
                log.debug("You have a malformed RTF stream. Are you sure you really want to be parsing it? It might not just be corrupted. It could be maliciously constructed.")
                return "\\ansi"

    def _get_codepage_num(self) -> int:
        """Extracts the unicode codepage number from the RTF streams header.
        """
        # This keyword should be emitted in the RTF header section right after the \ansi, \mac, \pc or \pca keyword. But, various document tags like \fbids often are thrown all over the header so we have to check the first group of headers for it.
        # Code page names from https://docs.microsoft.com/en-gb/windows/desktop/Intl/code-page-identifiers
        # Retrieved on 2020-12-18
        allowed_codepage_nums = set([37, 437, 500, 708, 709, 710, 720, 737, 775, 850, 852, 855, 857, 858, 860, 861, 862, 863, 864, 865, 866, 869, 870, 874, 875, 932, 936, 949, 950, 1026, 1047, 1140, 1141, 1142, 1143, 1144, 1145, 1146, 1147, 1148, 1149, 1200, 1201, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258, 1361, 10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10010, 10017, 10021, 10029, 10079, 10081, 10082, 12000, 12001, 20000, 20001, 20002, 20003, 20004, 20005, 20105, 20106, 20107, 20108, 20127, 20261, 20269, 20273, 20277, 20278, 20280, 20284, 20285, 20290, 20297, 20420, 20423, 20424, 20833, 20838, 20866, 20871, 20880, 20905, 20924, 20932, 20936, 20949, 21025, 21027, 21866, 28591, 28592, 28593, 28594, 28595, 28596, 28597, 28598, 28599, 28603, 28605, 29001, 38598, 50220, 50221, 50222, 50225, 50227, 50229, 50930, 50931, 50933, 50935, 50936, 50937, 50939, 51932, 51936, 51949, 51950, 52936, 54936, 57002, 57003, 57004, 57005, 57006, 57007, 57008, 57009, 57010, 57011, 65000, 65001])
        charset_check = re.compile(r'\\ansicpg([0-9]+)')
        main_headers = self._get_header_control_words_before_first_group()
        for unicode_charset in main_headers:
            cmatch = charset_check.match(unicode_charset.strip())
            if cmatch is not None:
                codepage_num = int(cmatch.groups()[0])
                if codepage_num in allowed_codepage_nums:
                    return codepage_num
                else:
                    raise MalformedRtf("Unsupported unicode codepage number `{}` found in the header".format(codepage_num))

        log.debug("No unicode codepage number found in the header. The following headers were checked: {0}".format(main_headers))
        raise MalformedRtf("No unicode codepage number found in the header")

    def _validate_FROM_in_doc_header(self):
        """Inspect the header to identify what type of content (html/plain text) is encapsulated within the document.

        NOTE: The de-encapsulating RTF reader inspects no more than the first 10 RTF tokens (that is, begin group marks and control words) in the input RTF document, in sequence, starting from the beginning of the RTF document. If one of the control words is the FROMHTML control word, the de-encapsulating RTF reader will conclude that the RTF document contains an encapsulated HTML document and stop further inspection. If one of the control words is the FROMTEXT control word, the de-encapsulating RTF reader concludes that the RTF document was produced from a plain text document and stops further inspection. - MS-OXRTFEX
        """
        cw_found = {"rtf1":False,
                    "from":False,
                    "fonttbl":False,
                    "malformed":False}
        # The de-encapsulating RTF reader SHOULD inspect no more than the first 10 RTF tokens (that is, begin group marks and control words) in the input RTF document, in sequence, starting from the beginning of the RTF document. This means more than just control words.
        first_ten_tokens = self.doc_tree.children[:10]
        operating_tokens = []
        found_token = None
        for token in first_ten_tokens:
            if isinstance(token, Token):
                operating_tokens.append(token)
            else:
                operating_tokens += [i for i in token.scan_values(lambda t: t.type in ('CONTROLWORD'))]
        log.debug("Header tokens being evaluated: {0}".format(operating_tokens))

        for token in operating_tokens:
            cw_found,found_token = self._check_from_token(token=token, cw_found=cw_found)
            if cw_found['from'] is True and cw_found["malformed"] is True:
                raise MalformedEncapsulatedRtf("RTF file looks like is was supposed to be encapsulated HTML/TEXT but the headers are malformed. Turn on debugging to see specific information")
            # Save content type token available for id-ing type of content later
            if found_token is not None:
                self._content_type_token = found_token

        if cw_found['from'] is False:
            log.debug("FROMHTML/TEXT control word not found in first 10 RTF tokens. This is not an HTML/TEXT encapsulated RTF document.")
            raise NotEncapsulatedRtf("FROMHTML/TEXT control word not found.")

    def _get_font_table(self) -> Tree:
        """Extract the font table group from the document"""
        for token in self.doc_tree.children[:20]:
            if isinstance(token, Tree):
                table_type = token.children[1].value
                if table_type == "\\fonttbl":
                    return token

    @staticmethod
    def _check_from_token(token, cw_found:dict) -> dict:
        """Checks if fromhtml1 or fromtext tokens are in the proper place in the header based on the state passed to it by the _validate_FROM_in_doc_header function.

        Parameters:
            cw_found: (dict): The state dictionary which is used to track the position of the from token within the header
                `cw_found = {"rtf1":<BOOL>, "from":<BOOL>, "fonttbl":<BOOL>, "malformed":<BOOL>}`
        """
        from_cws = ['\\fromhtml1', '\\fromtext']
        # This control word MUST appear before the \fonttbl control word and after the \rtf1 control word, as specified in [MSFT-RTF].
        rtf1_cw = "\\rtf1"
        found_token = None
        fonttbl_cw = "\\fonttbl"
        maltype = []
        if token.type == "CONTROLWORD":
            if token.value in from_cws:
                if cw_found['from'] is True:
                    cw_found["malformed"] = True
                    log.debug("Multiple FROM HTML/TXT tokens found in the header. This encapsulated RTF is malformed.")
                if cw_found['rtf1'] is True:
                    cw_found['from'] = True
                    found_token = token.value
                else:
                    log.debug("FROMHTML/TEXT control word found before rtf1 control word. That's not allowed in the RTF spec.")
                    cw_found['from'] = True
                    cw_found["malformed"] = True
            elif token.value == rtf1_cw:
                cw_found['rtf1'] = True
            elif token.value == fonttbl_cw:
                cw_found['fonttbl'] = True
                if cw_found['from'] != True:
                    log.debug("\\fonttbl code word found before FROMTML/TEXT was defined. This is not allowed for encapsulated HTML/TEXT. So... this is not encapsulated HTML/TEXT or it was badly encapsulated.")
                    cw_found["malformed"] = True
        return cw_found, found_token


    def _validate_rtf_doc_header(self):
        """Check if doc starts with a valid RTF header `\\rtf1`.

        "Before the de-encapsulating RTF reader tries to recognize the encapsulation, the reader SHOULD ensure that the document has a valid RTF document heading according to [MSFT-RTF] (that is, it starts with the character sequence "{\rtf1")." - MS-OXRTFEX
        """
        first_token = self.doc_tree.children[0].value
        if first_token != "\\rtf1":
            log.debug("RTF stream does not contain valid valid RTF document heading. The file must start with \"{\\rtf1\"")
            raise MalformedRtf("RTF stream does not start with {rtf1")
