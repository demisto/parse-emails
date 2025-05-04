REGEX_EMAIL = r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+[\b,]"
ENCODINGS_TYPES = {'utf-8', 'iso8859-1'}
USER_ENCODING = None
STRINGS_TO_REMOVE = ['\\u200a', '\\u200d']
DEFAULT_ENCODING = None
PROPS_ID_MAP = {
    "0x0001": {
        "data_type": "0x0102",
        "name": "TemplateData"
    },
    "0x0002": {
        "data_type": "0x000B",
        "name": "AlternateRecipientAllowed"
    },
    "0x0004": {
        "data_type": "0x0102",
        "name": "ScriptData"
    },
    "0x0005": {
        "data_type": "0x000B",
        "name": "AutoForwarded"
    },
    "0x000F": {
        "data_type": "0x0040",
        "name": "DeferredDeliveryTime"
    },
    "0x0010": {
        "data_type": "0x0040",
        "name": "DeliverTime"
    },
    "0x0015": {
        "data_type": "0x0040",
        "name": "ExpiryTime"
    },
    "0x0017": {
        "data_type": "0x0003",
        "name": "Importance"
    },
    "0x001A": {
        "data_type": "0x001F",
        "name": "MessageClass"
    },
    "0x0023": {
        "data_type": "0x000B",
        "name": "OriginatorDeliveryReportRequested"
    },
    "0x0025": {
        "data_type": "0x0102",
        "name": "ParentKey"
    },
    "0x0026": {
        "data_type": "0x0003",
        "name": "Priority"
    },
    "0x0029": {
        "data_type": "0x000B",
        "name": "ReadReceiptRequested"
    },
    "0x002A": {
        "data_type": "0x0040",
        "name": "ReceiptTime"
    },
    "0x002B": {
        "data_type": "0x000B",
        "name": "RecipientReassignmentProhibited"
    },
    "0x002E": {
        "data_type": "0x0003",
        "name": "OriginalSensitivity"
    },
    "0x0030": {
        "data_type": "0x0040",
        "name": "ReplyTime"
    },
    "0x0031": {
        "data_type": "0x0102",
        "name": "ReportTag"
    },
    "0x0032": {
        "data_type": "0x0040",
        "name": "ReportTime"
    },
    "0x0036": {
        "data_type": "0x0003",
        "name": "Sensitivity"
    },
    "0x0037": {
        "data_type": "0x001F",
        "name": "Subject"
    },
    "0x0039": {
        "data_type": "0x0040",
        "name": "ClientSubmitTime"
    },
    "0x003A": {
        "data_type": "0x001F",
        "name": "ReportName"
    },
    "0x003B": {
        "data_type": "0x0102",
        "name": "SentRepresentingSearchKey"
    },
    "0x003D": {
        "data_type": "0x001F",
        "name": "SubjectPrefix"
    },
    "0x003F": {
        "data_type": "0x0102",
        "name": "ReceivedByEntryId"
    },
    "0x0040": {
        "data_type": "0x001F",
        "name": "ReceivedByName"
    },
    "0x0041": {
        "data_type": "0x0102",
        "name": "SentRepresentingEntryId"
    },
    "0x0042": {
        "data_type": "0x001F",
        "name": "SentRepresentingName"
    },
    "0x0043": {
        "data_type": "0x0102",
        "name": "ReceivedRepresentingEntryId"
    },
    "0x0044": {
        "data_type": "0x001F",
        "name": "ReceivedRepresentingName"
    },
    "0x0045": {
        "data_type": "0x0102",
        "name": "ReportEntryId"
    },
    "0x0046": {
        "data_type": "0x0102",
        "name": "ReadReceiptEntryId"
    },
    "0x0047": {
        "data_type": "0x0102",
        "name": "MessageSubmissionId"
    },
    "0x0049": {
        "data_type": "0x001F",
        "name": "OriginalSubject"
    },
    "0x004B": {
        "data_type": "0x001F",
        "name": "OriginalMessageClass"
    },
    "0x004C": {
        "data_type": "0x0102",
        "name": "OriginalAuthorEntryId"
    },
    "0x004D": {
        "data_type": "0x001F",
        "name": "OriginalAuthorName"
    },
    "0x004E": {
        "data_type": "0x0040",
        "name": "OriginalSubmitTime"
    },
    "0x004F": {
        "data_type": "0x0102",
        "name": "ReplyRecipientEntries"
    },
    "0x0050": {
        "data_type": "0x001F",
        "name": "ReplyRecipientNames"
    },
    "0x0051": {
        "data_type": "0x0102",
        "name": "ReceivedBySearchKey"
    },
    "0x0052": {
        "data_type": "0x0102",
        "name": "ReceivedRepresentingSearchKey"
    },
    "0x0053": {
        "data_type": "0x0102",
        "name": "ReadReceiptSearchKey"
    },
    "0x0054": {
        "data_type": "0x0102",
        "name": "ReportSearchKey"
    },
    "0x0055": {
        "data_type": "0x0040",
        "name": "OriginalDeliveryTime"
    },
    "0x0057": {
        "data_type": "0x000B",
        "name": "MessageToMe"
    },
    "0x0058": {
        "data_type": "0x000B",
        "name": "MessageCcMe"
    },
    "0x0059": {
        "data_type": "0x000B",
        "name": "MessageRecipientMe"
    },
    "0x005A": {
        "data_type": "0x001F",
        "name": "OriginalSenderName"
    },
    "0x005B": {
        "data_type": "0x0102",
        "name": "OriginalSenderEntryId"
    },
    "0x005C": {
        "data_type": "0x0102",
        "name": "OriginalSenderSearchKey"
    },
    "0x005D": {
        "data_type": "0x001F",
        "name": "OriginalSentRepresentingName"
    },
    "0x005E": {
        "data_type": "0x0102",
        "name": "OriginalSentRepresentingEntryId"
    },
    "0x005F": {
        "data_type": "0x0102",
        "name": "OriginalSentRepresentingSearchKey"
    },
    "0x0060": {
        "data_type": "0x0040",
        "name": "StartDate"
    },
    "0x0061": {
        "data_type": "0x0040",
        "name": "EndDate"
    },
    "0x0062": {
        "data_type": "0x0003",
        "name": "OwnerAppointmentId"
    },
    "0x0063": {
        "data_type": "0x000B",
        "name": "ResponseRequested"
    },
    "0x0064": {
        "data_type": "0x001F",
        "name": "SentRepresentingAddressType"
    },
    "0x0065": {
        "data_type": "0x001F",
        "name": "SentRepresentingEmailAddress"
    },
    "0x0066": {
        "data_type": "0x001F",
        "name": "OriginalSenderAddressType"
    },
    "0x0067": {
        "data_type": "0x001F",
        "name": "OriginalSenderEmailAddress"
    },
    "0x0068": {
        "data_type": "0x001F",
        "name": "OriginalSentRepresentingAddressType"
    },
    "0x0069": {
        "data_type": "0x001F",
        "name": "OriginalSentRepresentingEmailAddress"
    },
    "0x0070": {
        "data_type": "0x001F",
        "name": "ConversationTopic"
    },
    "0x0071": {
        "data_type": "0x0102",
        "name": "ConversationIndex"
    },
    "0x0072": {
        "data_type": "0x001F",
        "name": "OriginalDisplayBcc"
    },
    "0x0073": {
        "data_type": "0x001F",
        "name": "OriginalDisplayCc"
    },
    "0x0074": {
        "data_type": "0x001F",
        "name": "OriginalDisplayTo"
    },
    "0x0075": {
        "data_type": "0x001F",
        "name": "ReceivedByAddressType"
    },
    "0x0076": {
        "data_type": "0x001F",
        "name": "ReceivedByEmailAddress"
    },
    "0x0077": {
        "data_type": "0x001F",
        "name": "ReceivedRepresentingAddressType"
    },
    "0x0078": {
        "data_type": "0x001F",
        "name": "ReceivedRepresentingEmailAddress"
    },
    "0x007D": {
        "data_type": "0x001F",
        "name": "TransportMessageHeaders"
    },
    "0x007F": {
        "data_type": "0x0102",
        "name": "TnefCorrelationKey"
    },
    "0x0080": {
        "data_type": "0x001F",
        "name": "ReportDisposition"
    },
    "0x0081": {
        "data_type": "0x001F",
        "name": "ReportDispositionMode"
    },
    "0x0807": {
        "data_type": "0x0003",
        "name": "AddressBookRoomCapacity"
    },
    "0x0809": {
        "data_type": "0x001F",
        "name": "AddressBookRoomDescription"
    },
    "0x0C04": {
        "data_type": "0x0003",
        "name": "NonDeliveryReportReasonCode"
    },
    "0x0C05": {
        "data_type": "0x0003",
        "name": "NonDeliveryReportDiagCode"
    },
    "0x0C06": {
        "data_type": "0x000B",
        "name": "NonReceiptNotificationRequested"
    },
    "0x0C08": {
        "data_type": "0x000B",
        "name": "OriginatorNonDeliveryReportRequested"
    },
    "0x0C15": {
        "data_type": "0x0003",
        "name": "RecipientType"
    },
    "0x0C17": {
        "data_type": "0x000B",
        "name": "ReplyRequested"
    },
    "0x0C19": {
        "data_type": "0x0102",
        "name": "SenderEntryId"
    },
    "0x0C1A": {
        "data_type": "0x001F",
        "name": "SenderName"
    },
    "0x0C1B": {
        "data_type": "0x001F",
        "name": "SupplementaryInfo"
    },
    "0x0C1D": {
        "data_type": "0x0102",
        "name": "SenderSearchKey"
    },
    "0x0C1E": {
        "data_type": "0x001F",
        "name": "SenderAddressType"
    },
    "0x0C1F": {
        "data_type": "0x001F",
        "name": "SenderEmailAddress"
    },
    "0x0C21": {
        "data_type": "0x001F",
        "name": "RemoteMessageTransferAgent"
    },
    "0x0E01": {
        "data_type": "0x000B",
        "name": "DeleteAfterSubmit"
    },
    "0x0E02": {
        "data_type": "0x001F",
        "name": "DisplayBcc"
    },
    "0x0E03": {
        "data_type": "0x001F",
        "name": "DisplayCc"
    },
    "0x0E04": {
        "data_type": "0x001F",
        "name": "DisplayTo"
    },
    "0x0E06": {
        "data_type": "0x0040",
        "name": "MessageDeliveryTime"
    },
    "0x0E07": {
        "data_type": "0x0003",
        "name": "MessageFlags"
    },
    "0x0E08": {
        "data_type": "0x0014",
        "name": "MessageSizeExtended"
    },
    "0x0E09": {
        "data_type": "0x0102",
        "name": "ParentEntryId"
    },
    "0x0E0F": {
        "data_type": "0x000B",
        "name": "Responsibility"
    },
    "0x0E12": {
        "data_type": "0x000D",
        "name": "MessageRecipients"
    },
    "0x0E13": {
        "data_type": "0x000D",
        "name": "MessageAttachments"
    },
    "0x0E17": {
        "data_type": "0x0003",
        "name": "MessageStatus"
    },
    "0x0E1B": {
        "data_type": "0x000B",
        "name": "HasAttachments"
    },
    "0x0E1D": {
        "data_type": "0x001F",
        "name": "NormalizedSubject"
    },
    "0x0E1F": {
        "data_type": "0x000B",
        "name": "RtfInSync"
    },
    "0x0E20": {
        "data_type": "0x0003",
        "name": "AttachSize"
    },
    "0x0E21": {
        "data_type": "0x0003",
        "name": "AttachNumber"
    },
    "0x0E28": {
        "data_type": "0x001F",
        "name": "PrimarySendAccount"
    },
    "0x0E29": {
        "data_type": "0x001F",
        "name": "NextSendAcct"
    },
    "0x0E2B": {
        "data_type": "0x0003",
        "name": "ToDoItemFlags"
    },
    "0x0E2C": {
        "data_type": "0x0102",
        "name": "SwappedToDoStore"
    },
    "0x0E2D": {
        "data_type": "0x0102",
        "name": "SwappedToDoData"
    },
    "0x0E69": {
        "data_type": "0x000B",
        "name": "Read"
    },
    "0x0E6A": {
        "data_type": "0x001F",
        "name": "SecurityDescriptorAsXml"
    },
    "0x0E79": {
        "data_type": "0x0003",
        "name": "TrustSender"
    },
    "0x0E84": {
        "data_type": "0x0102",
        "name": "ExchangeNTSecurityDescriptor"
    },
    "0x0E99": {
        "data_type": "0x0102",
        "name": "ExtendedRuleMessageActions"
    },
    "0x0E9A": {
        "data_type": "0x0102",
        "name": "ExtendedRuleMessageCondition"
    },
    "0x0E9B": {
        "data_type": "0x0003",
        "name": "ExtendedRuleSizeLimit"
    },
    "0x0FF4": {
        "data_type": "0x0003",
        "name": "Access"
    },
    "0x0FF5": {
        "data_type": "0x0003",
        "name": "RowType"
    },
    "0x0FF6": {
        "data_type": "0x0102",
        "name": "InstanceKey"
    },
    "0x0FF7": {
        "data_type": "0x0003",
        "name": "AccessLevel"
    },
    "0x0FF8": {
        "data_type": "0x0102",
        "name": "MappingSignature"
    },
    "0x0FF9": {
        "data_type": "0x0102",
        "name": "RecordKey"
    },
    "0x0FFB": {
        "data_type": "0x0102",
        "name": "StoreEntryId"
    },
    "0x0FFE": {
        "data_type": "0x0003",
        "name": "ObjectType"
    },
    "0x0FFF": {
        "data_type": "0x0102",
        "name": "EntryId"
    },
    "0x1000": {
        "data_type": "0x001F",
        "name": "Body"
    },
    "0x1001": {
        "data_type": "0x001F",
        "name": "ReportText"
    },
    "0x1009": {
        "data_type": "0x0102",
        "name": "RtfCompressed"
    },
    "0x1013": {
        "data_type": "0x0102",
        "name": "Html"
    },
    "0x1014": {
        "data_type": "0x001F",
        "name": "BodyContentLocation"
    },
    "0x1015": {
        "data_type": "0x001F",
        "name": "BodyContentId"
    },
    "0x1016": {
        "data_type": "0x0003",
        "name": "NativeBody"
    },
    "0x1035": {
        "data_type": "0x001F",
        "name": "InternetMessageId"
    },
    "0x1039": {
        "data_type": "0x001F",
        "name": "InternetReferences"
    },
    "0x1042": {
        "data_type": "0x001F",
        "name": "InReplyToId"
    },
    "0x1043": {
        "data_type": "0x001F",
        "name": "ListHelp"
    },
    "0x1044": {
        "data_type": "0x001F",
        "name": "ListSubscribe"
    },
    "0x1045": {
        "data_type": "0x001F",
        "name": "ListUnsubscribe"
    },
    "0x1046": {
        "data_type": "0x001F",
        "name": "OriginalMessageId"
    },
    "0x1080": {
        "data_type": "0x0003",
        "name": "IconIndex"
    },
    "0x1081": {
        "data_type": "0x0003",
        "name": "LastVerbExecuted"
    },
    "0x1082": {
        "data_type": "0x0040",
        "name": "LastVerbExecutionTime"
    },
    "0x1090": {
        "data_type": "0x0003",
        "name": "FlagStatus"
    },
    "0x1091": {
        "data_type": "0x0040",
        "name": "FlagCompleteTime"
    },
    "0x1095": {
        "data_type": "0x0003",
        "name": "FollowupIcon"
    },
    "0x1096": {
        "data_type": "0x0003",
        "name": "BlockStatus"
    },
    "0x10C3": {
        "data_type": "0x0040",
        "name": "ICalendarStartTime"
    },
    "0x10C4": {
        "data_type": "0x0040",
        "name": "ICalendarEndTime"
    },
    "0x10C5": {
        "data_type": "0x0040",
        "name": "CdoRecurrenceid"
    },
    "0x10CA": {
        "data_type": "0x0040",
        "name": "ICalendarReminderNextTime"
    },
    "0x10F4": {
        "data_type": "0x000B",
        "name": "AttributeHidden"
    },
    "0x10F6": {
        "data_type": "0x000B",
        "name": "AttributeReadOnly"
    },
    "0x3000": {
        "data_type": "0x0003",
        "name": "Rowid"
    },
    "0x3001": {
        "data_type": "0x001F",
        "name": "DisplayName"
    },
    "0x3002": {
        "data_type": "0x001F",
        "name": "AddressType"
    },
    "0x3003": {
        "data_type": "0x001F",
        "name": "EmailAddress"
    },
    "0x3004": {
        "data_type": "0x001F",
        "name": "Comment"
    },
    "0x3005": {
        "data_type": "0x0003",
        "name": "Depth"
    },
    "0x3007": {
        "data_type": "0x0040",
        "name": "CreationTime"
    },
    "0x3008": {
        "data_type": "0x0040",
        "name": "LastModificationTime"
    },
    "0x300B": {
        "data_type": "0x0102",
        "name": "SearchKey"
    },
    "0x3010": {
        "data_type": "0x0102",
        "name": "TargetEntryId"
    },
    "0x3013": {
        "data_type": "0x0102",
        "name": "ConversationId"
    },
    "0x3016": {
        "data_type": "0x000B",
        "name": "ConversationIndexTracking"
    },
    "0x3018": {
        "data_type": "0x0102",
        "name": "ArchiveTag"
    },
    "0x3019": {
        "data_type": "0x0102",
        "name": "PolicyTag"
    },
    "0x301A": {
        "data_type": "0x0003",
        "name": "RetentionPeriod"
    },
    "0x301B": {
        "data_type": "0x0102",
        "name": "StartDateEtc"
    },
    "0x301C": {
        "data_type": "0x0040",
        "name": "RetentionDate"
    },
    "0x301D": {
        "data_type": "0x0003",
        "name": "RetentionFlags"
    },
    "0x301E": {
        "data_type": "0x0003",
        "name": "ArchivePeriod"
    },
    "0x301F": {
        "data_type": "0x0040",
        "name": "ArchiveDate"
    },
    "0x340D": {
        "data_type": "0x0003",
        "name": "StoreSupportMask"
    },
    "0x340E": {
        "data_type": "0x0003",
        "name": "StoreState"
    },
    "0x3600": {
        "data_type": "0x0003",
        "name": "ContainerFlags"
    },
    "0x3601": {
        "data_type": "0x0003",
        "name": "FolderType"
    },
    "0x3602": {
        "data_type": "0x0003",
        "name": "ContentCount"
    },
    "0x3603": {
        "data_type": "0x0003",
        "name": "ContentUnreadCount"
    },
    "0x3609": {
        "data_type": "0x000B",
        "name": "Selectable"
    },
    "0x360A": {
        "data_type": "0x000B",
        "name": "Subfolders"
    },
    "0x360C": {
        "data_type": "0x001F",
        "name": "Anr"
    },
    "0x360E": {
        "data_type": "0x000D",
        "name": "ContainerHierarchy"
    },
    "0x360F": {
        "data_type": "0x000D",
        "name": "ContainerContents"
    },
    "0x3610": {
        "data_type": "0x000D",
        "name": "FolderAssociatedContents"
    },
    "0x3613": {
        "data_type": "0x001F",
        "name": "ContainerClass"
    },
    "0x36D0": {
        "data_type": "0x0102",
        "name": "IpmAppointmentEntryId"
    },
    "0x36D1": {
        "data_type": "0x0102",
        "name": "IpmContactEntryId"
    },
    "0x36D2": {
        "data_type": "0x0102",
        "name": "IpmJournalEntryId"
    },
    "0x36D3": {
        "data_type": "0x0102",
        "name": "IpmNoteEntryId"
    },
    "0x36D4": {
        "data_type": "0x0102",
        "name": "IpmTaskEntryId"
    },
    "0x36D5": {
        "data_type": "0x0102",
        "name": "RemindersOnlineEntryId"
    },
    "0x36D7": {
        "data_type": "0x0102",
        "name": "IpmDraftsEntryId"
    },
    "0x36D8": {
        "data_type": "0x1102",
        "name": "AdditionalRenEntryIds"
    },
    "0x36D9": {
        "data_type": "0x0102",
        "name": "AdditionalRenEntryIdsEx"
    },
    "0x36DA": {
        "data_type": "0x0102",
        "name": "ExtendedFolderFlags"
    },
    "0x36E2": {
        "data_type": "0x0003",
        "name": "OrdinalMost"
    },
    "0x36E4": {
        "data_type": "0x1102",
        "name": "FreeBusyEntryIds"
    },
    "0x36E5": {
        "data_type": "0x001F",
        "name": "DefaultPostMessageClass"
    },
    "0x3701": {
        "data_type": "0x000D",
        "name": "AttachDataObject"
    },
    "0x3702": {
        "data_type": "0x0102",
        "name": "AttachEncoding"
    },
    "0x3703": {
        "data_type": "0x001F",
        "name": "AttachExtension"
    },
    "0x3704": {
        "data_type": "0x001F",
        "name": "AttachFilename"
    },
    "0x3705": {
        "data_type": "0x0003",
        "name": "AttachMethod"
    },
    "0x3707": {
        "data_type": "0x001F",
        "name": "AttachLongFilename"
    },
    "0x3708": {
        "data_type": "0x001F",
        "name": "AttachPathname"
    },
    "0x3709": {
        "data_type": "0x0102",
        "name": "AttachRendering"
    },
    "0x370A": {
        "data_type": "0x0102",
        "name": "AttachTag"
    },
    "0x370B": {
        "data_type": "0x0003",
        "name": "RenderingPosition"
    },
    "0x370C": {
        "data_type": "0x001F",
        "name": "AttachTransportName"
    },
    "0x370D": {
        "data_type": "0x001F",
        "name": "AttachLongPathname"
    },
    "0x370E": {
        "data_type": "0x001F",
        "name": "AttachMimeTag"
    },
    "0x370F": {
        "data_type": "0x0102",
        "name": "AttachAdditionalInformation"
    },
    "0x3711": {
        "data_type": "0x001F",
        "name": "AttachContentBase"
    },
    "0x3712": {
        "data_type": "0x001F",
        "name": "AttachContentId"
    },
    "0x3713": {
        "data_type": "0x001F",
        "name": "AttachContentLocation"
    },
    "0x3714": {
        "data_type": "0x0003",
        "name": "AttachFlags"
    },
    "0x3719": {
        "data_type": "0x001F",
        "name": "AttachPayloadProviderGuidString"
    },
    "0x371A": {
        "data_type": "0x001F",
        "name": "AttachPayloadClass"
    },
    "0x371B": {
        "data_type": "0x001F",
        "name": "TextAttachmentCharset"
    },
    "0x3900": {
        "data_type": "0x0003",
        "name": "DisplayType"
    },
    "0x3902": {
        "data_type": "0x0102",
        "name": "Templateid"
    },
    "0x3905": {
        "data_type": "0x0003",
        "name": "DisplayTypeEx"
    },
    "0x39FE": {
        "data_type": "0x001F",
        "name": "SmtpAddress"
    },
    "0x39FF": {
        "data_type": "0x001F",
        "name": "AddressBookDisplayNamePrintable"
    },
    "0x3A00": {
        "data_type": "0x001F",
        "name": "Account"
    },
    "0x3A02": {
        "data_type": "0x001F",
        "name": "CallbackTelephoneNumber"
    },
    "0x3A05": {
        "data_type": "0x001F",
        "name": "Generation"
    },
    "0x3A06": {
        "data_type": "0x001F",
        "name": "GivenName"
    },
    "0x3A07": {
        "data_type": "0x001F",
        "name": "GovernmentIdNumber"
    },
    "0x3A08": {
        "data_type": "0x001F",
        "name": "BusinessTelephoneNumber"
    },
    "0x3A09": {
        "data_type": "0x001F",
        "name": "HomeTelephoneNumber"
    },
    "0x3A0A": {
        "data_type": "0x001F",
        "name": "Initials"
    },
    "0x3A0B": {
        "data_type": "0x001F",
        "name": "Keyword"
    },
    "0x3A0C": {
        "data_type": "0x001F",
        "name": "Language"
    },
    "0x3A0D": {
        "data_type": "0x001F",
        "name": "Location"
    },
    "0x3A0F": {
        "data_type": "0x001F",
        "name": "MessageHandlingSystemCommonName"
    },
    "0x3A10": {
        "data_type": "0x001F",
        "name": "OrganizationalIdNumber"
    },
    "0x3A11": {
        "data_type": "0x001F",
        "name": "Surname"
    },
    "0x3A12": {
        "data_type": "0x0102",
        "name": "OriginalEntryId"
    },
    "0x3A15": {
        "data_type": "0x001F",
        "name": "PostalAddress"
    },
    "0x3A16": {
        "data_type": "0x001F",
        "name": "CompanyName"
    },
    "0x3A17": {
        "data_type": "0x001F",
        "name": "Title"
    },
    "0x3A18": {
        "data_type": "0x001F",
        "name": "DepartmentName"
    },
    "0x3A19": {
        "data_type": "0x001F",
        "name": "OfficeLocation"
    },
    "0x3A1A": {
        "data_type": "0x001F",
        "name": "PrimaryTelephoneNumber"
    },
    "0x3A1B": {
        "data_type": "0x101F",
        "name": "Business2TelephoneNumbers"
    },
    "0x3A1C": {
        "data_type": "0x001F",
        "name": "MobileTelephoneNumber"
    },
    "0x3A1D": {
        "data_type": "0x001F",
        "name": "RadioTelephoneNumber"
    },
    "0x3A1E": {
        "data_type": "0x001F",
        "name": "CarTelephoneNumber"
    },
    "0x3A1F": {
        "data_type": "0x001F",
        "name": "OtherTelephoneNumber"
    },
    "0x3A20": {
        "data_type": "0x001F",
        "name": "TransmittableDisplayName"
    },
    "0x3A21": {
        "data_type": "0x001F",
        "name": "PagerTelephoneNumber"
    },
    "0x3A22": {
        "data_type": "0x0102",
        "name": "UserCertificate"
    },
    "0x3A23": {
        "data_type": "0x001F",
        "name": "PrimaryFaxNumber"
    },
    "0x3A24": {
        "data_type": "0x001F",
        "name": "BusinessFaxNumber"
    },
    "0x3A25": {
        "data_type": "0x001F",
        "name": "HomeFaxNumber"
    },
    "0x3A26": {
        "data_type": "0x001F",
        "name": "Country"
    },
    "0x3A27": {
        "data_type": "0x001F",
        "name": "Locality"
    },
    "0x3A28": {
        "data_type": "0x001F",
        "name": "StateOrProvince"
    },
    "0x3A29": {
        "data_type": "0x001F",
        "name": "StreetAddress"
    },
    "0x3A2A": {
        "data_type": "0x001F",
        "name": "PostalCode"
    },
    "0x3A2B": {
        "data_type": "0x001F",
        "name": "PostOfficeBox"
    },
    "0x3A2C": {
        "data_type": "0x001F; PtypMultipleBinary, 0x1102",
        "name": "TelexNumber"
    },
    "0x3A2D": {
        "data_type": "0x001F",
        "name": "IsdnNumber"
    },
    "0x3A2E": {
        "data_type": "0x001F",
        "name": "AssistantTelephoneNumber"
    },
    "0x3A2F": {
        "data_type": "0x101F",
        "name": "Home2TelephoneNumbers"
    },
    "0x3A30": {
        "data_type": "0x001F",
        "name": "Assistant"
    },
    "0x3A40": {
        "data_type": "0x000B",
        "name": "SendRichInfo"
    },
    "0x3A41": {
        "data_type": "0x0040",
        "name": "WeddingAnniversary"
    },
    "0x3A42": {
        "data_type": "0x0040",
        "name": "Birthday"
    },
    "0x3A43": {
        "data_type": "0x001F",
        "name": "Hobbies"
    },
    "0x3A44": {
        "data_type": "0x001F",
        "name": "MiddleName"
    },
    "0x3A45": {
        "data_type": "0x001F",
        "name": "DisplayNamePrefix"
    },
    "0x3A46": {
        "data_type": "0x001F",
        "name": "Profession"
    },
    "0x3A47": {
        "data_type": "0x001F",
        "name": "ReferredByName"
    },
    "0x3A48": {
        "data_type": "0x001F",
        "name": "SpouseName"
    },
    "0x3A49": {
        "data_type": "0x001F",
        "name": "ComputerNetworkName"
    },
    "0x3A4A": {
        "data_type": "0x001F",
        "name": "CustomerId"
    },
    "0x3A4B": {
        "data_type": "0x001F",
        "name": "TelecommunicationsDeviceForDeafTelephoneNumber"
    },
    "0x3A4C": {
        "data_type": "0x001F",
        "name": "FtpSite"
    },
    "0x3A4D": {
        "data_type": "0x0002",
        "name": "Gender"
    },
    "0x3A4E": {
        "data_type": "0x001F",
        "name": "ManagerName"
    },
    "0x3A4F": {
        "data_type": "0x001F",
        "name": "Nickname"
    },
    "0x3A50": {
        "data_type": "0x001F",
        "name": "PersonalHomePage"
    },
    "0x3A51": {
        "data_type": "0x001F",
        "name": "BusinessHomePage"
    },
    "0x3A57": {
        "data_type": "0x001F",
        "name": "CompanyMainTelephoneNumber"
    },
    "0x3A58": {
        "data_type": "0x101F",
        "name": "ChildrensNames"
    },
    "0x3A59": {
        "data_type": "0x001F",
        "name": "HomeAddressCity"
    },
    "0x3A5A": {
        "data_type": "0x001F",
        "name": "HomeAddressCountry"
    },
    "0x3A5B": {
        "data_type": "0x001F",
        "name": "HomeAddressPostalCode"
    },
    "0x3A5C": {
        "data_type": "0x001F",
        "name": "HomeAddressStateOrProvince"
    },
    "0x3A5D": {
        "data_type": "0x001F",
        "name": "HomeAddressStreet"
    },
    "0x3A5E": {
        "data_type": "0x001F",
        "name": "HomeAddressPostOfficeBox"
    },
    "0x3A5F": {
        "data_type": "0x001F",
        "name": "OtherAddressCity"
    },
    "0x3A60": {
        "data_type": "0x001F",
        "name": "OtherAddressCountry"
    },
    "0x3A61": {
        "data_type": "0x001F",
        "name": "OtherAddressPostalCode"
    },
    "0x3A62": {
        "data_type": "0x001F",
        "name": "OtherAddressStateOrProvince"
    },
    "0x3A63": {
        "data_type": "0x001F",
        "name": "OtherAddressStreet"
    },
    "0x3A64": {
        "data_type": "0x001F",
        "name": "OtherAddressPostOfficeBox"
    },
    "0x3A70": {
        "data_type": "0x1102",
        "name": "UserX509Certificate"
    },
    "0x3A71": {
        "data_type": "0x0003",
        "name": "SendInternetEncoding"
    },
    "0x3F08": {
        "data_type": "0x0003",
        "name": "InitialDetailsPane"
    },
    "0x3FDE": {
        "data_type": "0x0003",
        "name": "InternetCodepage"
    },
    "0x3FDF": {
        "data_type": "0x0003",
        "name": "AutoResponseSuppress"
    },
    "0x3FE0": {
        "data_type": "0x0102",
        "name": "AccessControlListData"
    },
    "0x3FE3": {
        "data_type": "0x000B",
        "name": "DelegatedByRule"
    },
    "0x3FE7": {
        "data_type": "0x0003",
        "name": "ResolveMethod"
    },
    "0x3FEA": {
        "data_type": "0x000B",
        "name": "HasDeferredActionMessages"
    },
    "0x3FEB": {
        "data_type": "0x0003",
        "name": "DeferredSendNumber"
    },
    "0x3FEC": {
        "data_type": "0x0003",
        "name": "DeferredSendUnits"
    },
    "0x3FED": {
        "data_type": "0x0003",
        "name": "ExpiryNumber"
    },
    "0x3FEE": {
        "data_type": "0x0003",
        "name": "ExpiryUnits"
    },
    "0x3FEF": {
        "data_type": "0x0040",
        "name": "DeferredSendTime"
    },
    "0x3FF0": {
        "data_type": "0x0102",
        "name": "ConflictEntryId"
    },
    "0x3FF1": {
        "data_type": "0x0003",
        "name": "MessageLocaleId"
    },
    "0x3FF8": {
        "data_type": "0x001F",
        "name": "CreatorName"
    },
    "0x3FF9": {
        "data_type": "0x0102",
        "name": "CreatorEntryId"
    },
    "0x3FFA": {
        "data_type": "0x001F",
        "name": "LastModifierName"
    },
    "0x3FFB": {
        "data_type": "0x0102",
        "name": "LastModifierEntryId"
    },
    "0x3FFD": {
        "data_type": "0x0003",
        "name": "MessageCodepage"
    },
    "0x401A": {
        "data_type": "0x0003",
        "name": "SentRepresentingFlags"
    },
    "0x4029": {
        "data_type": "0x001F",
        "name": "ReadReceiptAddressType"
    },
    "0x402A": {
        "data_type": "0x001F",
        "name": "ReadReceiptEmailAddress"
    },
    "0x402B": {
        "data_type": "0x001F",
        "name": "ReadReceiptName"
    },
    "0x4076": {
        "data_type": "0x0003",
        "name": "ContentFilterSpamConfidenceLevel"
    },
    "0x4079": {
        "data_type": "0x0003",
        "name": "SenderIdStatus"
    },
    "0x4082": {
        "data_type": "0x0040",
        "name": "HierRev"
    },
    "0x4083": {
        "data_type": "0x001F",
        "name": "PurportedSenderDomain"
    },
    "0x5902": {
        "data_type": "0x0003",
        "name": "InternetMailOverrideFormat"
    },
    "0x5909": {
        "data_type": "0x0003",
        "name": "MessageEditorFormat"
    },
    "0x5D01": {
        "data_type": "0x001F",
        "name": "SenderSmtpAddress"
    },
    "0x5D02": {
        "data_type": "0x001F",
        "name": "SentRepresentingSmtpAddress"
    },
    "0x5D05": {
        "data_type": "0x001F",
        "name": "ReadReceiptSmtpAddress"
    },
    "0x5D07": {
        "data_type": "0x001F",
        "name": "ReceivedBySmtpAddress"
    },
    "0x5D08": {
        "data_type": "0x001F",
        "name": "ReceivedRepresentingSmtpAddress"
    },
    "0x5FDF": {
        "data_type": "0x0003",
        "name": "RecipientOrder"
    },
    "0x5FE1": {
        "data_type": "0x000B",
        "name": "RecipientProposed"
    },
    "0x5FE3": {
        "data_type": "0x0040",
        "name": "RecipientProposedStartTime"
    },
    "0x5FE4": {
        "data_type": "0x0040",
        "name": "RecipientProposedEndTime"
    },
    "0x5FF6": {
        "data_type": "0x001F",
        "name": "RecipientDisplayName"
    },
    "0x5FF7": {
        "data_type": "0x0102",
        "name": "RecipientEntryId"
    },
    "0x5FFB": {
        "data_type": "0x0040",
        "name": "RecipientTrackStatusTime"
    },
    "0x5FFD": {
        "data_type": "0x0003",
        "name": "RecipientFlags"
    },
    "0x5FFF": {
        "data_type": "0x0003",
        "name": "RecipientTrackStatus"
    },
    "0x6100": {
        "data_type": "0x0003",
        "name": "JunkIncludeContacts"
    },
    "0x6101": {
        "data_type": "0x0003",
        "name": "JunkThreshold"
    },
    "0x6102": {
        "data_type": "0x0003",
        "name": "JunkPermanentlyDelete"
    },
    "0x6103": {
        "data_type": "0x0003",
        "name": "JunkAddRecipientsToSafeSendersList"
    },
    "0x6107": {
        "data_type": "0x000B",
        "name": "JunkPhishingEnableLinks"
    },
    "0x64F0": {
        "data_type": "0x0102",
        "name": "MimeSkeleton"
    },
    "0x65C2": {
        "data_type": "0x0102",
        "name": "ReplyTemplateId"
    },
    "0x65E0": {
        "data_type": "0x0102",
        "name": "SourceKey"
    },
    "0x65E1": {
        "data_type": "0x0102",
        "name": "ParentSourceKey"
    },
    "0x65E2": {
        "data_type": "0x0102",
        "name": "ChangeKey"
    },
    "0x65E3": {
        "data_type": "0x0102",
        "name": "PredecessorChangeList"
    },
    "0x65E9": {
        "data_type": "0x0003",
        "name": "RuleMessageState"
    },
    "0x65EA": {
        "data_type": "0x0003",
        "name": "RuleMessageUserFlags"
    },
    "0x65EB": {
        "data_type": "0x001F",
        "name": "RuleMessageProvider"
    },
    "0x65EC": {
        "data_type": "0x001F",
        "name": "RuleMessageName"
    },
    "0x65ED": {
        "data_type": "0x0003",
        "name": "RuleMessageLevel"
    },
    "0x65EE": {
        "data_type": "0x0102",
        "name": "RuleMessageProviderData"
    },
    "0x65F3": {
        "data_type": "0x0003",
        "name": "RuleMessageSequence"
    },
    "0x6619": {
        "data_type": "0x0102",
        "name": "UserEntryId"
    },
    "0x661B": {
        "data_type": "0x0102",
        "name": "MailboxOwnerEntryId"
    },
    "0x661C": {
        "data_type": "0x001F",
        "name": "MailboxOwnerName"
    },
    "0x661D": {
        "data_type": "0x000B",
        "name": "OutOfOfficeState"
    },
    "0x6622": {
        "data_type": "0x0102",
        "name": "SchedulePlusFreeBusyEntryId"
    },
    "0x6638": {
        "data_type": "0x0102",
        "name": "SerializedReplidGuidMap"
    },
    "0x6639": {
        "data_type": "0x0003",
        "name": "Rights"
    },
    "0x663A": {
        "data_type": "0x000B",
        "name": "HasRules"
    },
    "0x663B": {
        "data_type": "0x0102",
        "name": "AddressBookEntryId"
    },
    "0x663E": {
        "data_type": "0x0003",
        "name": "HierarchyChangeNumber"
    },
    "0x6645": {
        "data_type": "0x0102",
        "name": "ClientActions"
    },
    "0x6646": {
        "data_type": "0x0102",
        "name": "DamOriginalEntryId"
    },
    "0x6647": {
        "data_type": "0x000B",
        "name": "DamBackPatched"
    },
    "0x6648": {
        "data_type": "0x0003",
        "name": "RuleError"
    },
    "0x6649": {
        "data_type": "0x0003",
        "name": "RuleActionType"
    },
    "0x664A": {
        "data_type": "0x000B",
        "name": "HasNamedProperties"
    },
    "0x6650": {
        "data_type": "0x0003",
        "name": "RuleActionNumber"
    },
    "0x6651": {
        "data_type": "0x0102",
        "name": "RuleFolderEntryId"
    },
    "0x666A": {
        "data_type": "0x0003",
        "name": "ProhibitReceiveQuota"
    },
    "0x666C": {
        "data_type": "0x000B",
        "name": "InConflict"
    },
    "0x666D": {
        "data_type": "0x0003",
        "name": "MaximumSubmitMessageSize"
    },
    "0x666E": {
        "data_type": "0x0003",
        "name": "ProhibitSendQuota"
    },
    "0x6671": {
        "data_type": "0x0014",
        "name": "MemberId"
    },
    "0x6672": {
        "data_type": "0x001F",
        "name": "MemberName"
    },
    "0x6673": {
        "data_type": "0x0003",
        "name": "MemberRights"
    },
    "0x6674": {
        "data_type": "0x0014",
        "name": "RuleId"
    },
    "0x6675": {
        "data_type": "0x0102",
        "name": "RuleIds"
    },
    "0x6676": {
        "data_type": "0x0003",
        "name": "RuleSequence"
    },
    "0x6677": {
        "data_type": "0x0003",
        "name": "RuleState"
    },
    "0x6678": {
        "data_type": "0x0003",
        "name": "RuleUserFlags"
    },
    "0x6679": {
        "data_type": "0x00FD",
        "name": "RuleCondition"
    },
    "0x6680": {
        "data_type": "0x00FE",
        "name": "RuleActions"
    },
    "0x6681": {
        "data_type": "0x001F",
        "name": "RuleProvider"
    },
    "0x6682": {
        "data_type": "0x001F",
        "name": "RuleName"
    },
    "0x6683": {
        "data_type": "0x0003",
        "name": "RuleLevel"
    },
    "0x6684": {
        "data_type": "0x0102",
        "name": "RuleProviderData"
    },
    "0x668F": {
        "data_type": "0x0040",
        "name": "DeletedOn"
    },
    "0x66A1": {
        "data_type": "0x0003",
        "name": "LocaleId"
    },
    "0x66A8": {
        "data_type": "0x0003",
        "name": "FolderFlags"
    },
    "0x66C3": {
        "data_type": "0x0003",
        "name": "CodePageId"
    },
    "0x6704": {
        "data_type": "0x000D",
        "name": "AddressBookManageDistributionList"
    },
    "0x6705": {
        "data_type": "0x0003",
        "name": "SortLocaleId"
    },
    "0x6709": {
        "data_type": "0x0040",
        "name": "LocalCommitTime"
    },
    "0x670A": {
        "data_type": "0x0040",
        "name": "LocalCommitTimeMax"
    },
    "0x670B": {
        "data_type": "0x0003",
        "name": "DeletedCountTotal"
    },
    "0x670E": {
        "data_type": "0x001F",
        "name": "FlatUrlName"
    },
    "0x6740": {
        "data_type": "0x00FB",
        "name": "SentMailSvrEID"
    },
    "0x6741": {
        "data_type": "0x00FB",
        "name": "DeferredActionMessageOriginalEntryId"
    },
    "0x6748": {
        "data_type": "0x0014",
        "name": "FolderId"
    },
    "0x6749": {
        "data_type": "0x0014",
        "name": "ParentFolderId"
    },
    "0x674A": {
        "data_type": "0x0014",
        "name": "Mid"
    },
    "0x674D": {
        "data_type": "0x0014",
        "name": "InstID"
    },
    "0x674E": {
        "data_type": "0x0003",
        "name": "InstanceNum"
    },
    "0x674F": {
        "data_type": "0x0014",
        "name": "AddressBookMessageId"
    },
    "0x67A4": {
        "data_type": "0x0014",
        "name": "ChangeNumber"
    },
    "0x67AA": {
        "data_type": "0x000B",
        "name": "Associated"
    },
    "0x6800": {
        "data_type": "0x001F",
        "name": "OfflineAddressBookName"
    },
    "0x6801": {
        "data_type": "0x0003",
        "name": "VoiceMessageDuration"
    },
    "0x6802": {
        "data_type": "0x001F",
        "name": "SenderTelephoneNumber"
    },
    "0x6803": {
        "data_type": "0x001F",
        "name": "VoiceMessageSenderName"
    },
    "0x6804": {
        "data_type": "0x001E",
        "name": "OfflineAddressBookDistinguishedName"
    },
    "0x6805": {
        "data_type": "0x001F",
        "name": "VoiceMessageAttachmentOrder"
    },
    "0x6806": {
        "data_type": "0x001F",
        "name": "CallId"
    },
    "0x6820": {
        "data_type": "0x001F",
        "name": "ReportingMessageTransferAgent"
    },
    "0x6834": {
        "data_type": "0x0003",
        "name": "SearchFolderLastUsed"
    },
    "0x683A": {
        "data_type": "0x0003",
        "name": "SearchFolderExpiration"
    },
    "0x6841": {
        "data_type": "0x0003",
        "name": "SearchFolderTemplateId"
    },
    "0x6842": {
        "data_type": "0x0102",
        "name": "WlinkGroupHeaderID"
    },
    "0x6843": {
        "data_type": "0x000B",
        "name": "ScheduleInfoDontMailDelegates"
    },
    "0x6844": {
        "data_type": "0x0102",
        "name": "SearchFolderRecreateInfo"
    },
    "0x6845": {
        "data_type": "0x0102",
        "name": "SearchFolderDefinition"
    },
    "0x6846": {
        "data_type": "0x0003",
        "name": "SearchFolderStorageType"
    },
    "0x6847": {
        "data_type": "0x0003",
        "name": "WlinkSaveStamp"
    },
    "0x6848": {
        "data_type": "0x0003",
        "name": "SearchFolderEfpFlags"
    },
    "0x6849": {
        "data_type": "0x0003",
        "name": "WlinkType"
    },
    "0x684A": {
        "data_type": "0x0003",
        "name": "WlinkFlags"
    },
    "0x684B": {
        "data_type": "0x0102",
        "name": "WlinkOrdinal"
    },
    "0x684C": {
        "data_type": "0x0102",
        "name": "WlinkEntryId"
    },
    "0x684D": {
        "data_type": "0x0102",
        "name": "WlinkRecordKey"
    },
    "0x684E": {
        "data_type": "0x0102",
        "name": "WlinkStoreEntryId"
    },
    "0x684F": {
        "data_type": "0x0102",
        "name": "WlinkFolderType"
    },
    "0x6850": {
        "data_type": "0x0102",
        "name": "WlinkGroupClsid"
    },
    "0x6851": {
        "data_type": "0x001F",
        "name": "WlinkGroupName"
    },
    "0x6852": {
        "data_type": "0x0003",
        "name": "WlinkSection"
    },
    "0x6853": {
        "data_type": "0x0003",
        "name": "WlinkCalendarColor"
    },
    "0x6854": {
        "data_type": "0x0102",
        "name": "WlinkAddressBookEID"
    },
    "0x6855": {
        "data_type": "0x1003",
        "name": "ScheduleInfoMonthsAway"
    },
    "0x6856": {
        "data_type": "0x1102",
        "name": "ScheduleInfoFreeBusyAway"
    },
    "0x6868": {
        "data_type": "0x0040",
        "name": "FreeBusyRangeTimestamp"
    },
    "0x6869": {
        "data_type": "0x0003",
        "name": "FreeBusyCountMonths"
    },
    "0x686A": {
        "data_type": "0x0102",
        "name": "ScheduleInfoAppointmentTombstone"
    },
    "0x686B": {
        "data_type": "0x1003",
        "name": "DelegateFlags"
    },
    "0x686C": {
        "data_type": "0x0102",
        "name": "ScheduleInfoFreeBusy"
    },
    "0x686D": {
        "data_type": "0x000B",
        "name": "ScheduleInfoAutoAcceptAppointments"
    },
    "0x686E": {
        "data_type": "0x000B",
        "name": "ScheduleInfoDisallowRecurringAppts"
    },
    "0x686F": {
        "data_type": "0x000B",
        "name": "ScheduleInfoDisallowOverlappingAppts"
    },
    "0x6890": {
        "data_type": "0x0102",
        "name": "WlinkClientID"
    },
    "0x6891": {
        "data_type": "0x0102",
        "name": "WlinkAddressBookStoreEID"
    },
    "0x6892": {
        "data_type": "0x0003",
        "name": "WlinkROGroupType"
    },
    "0x7001": {
        "data_type": "0x0102",
        "name": "ViewDescriptorBinary"
    },
    "0x7002": {
        "data_type": "0x001F",
        "name": "ViewDescriptorStrings"
    },
    "0x7006": {
        "data_type": "0x001F",
        "name": "ViewDescriptorName"
    },
    "0x7007": {
        "data_type": "0x0003",
        "name": "ViewDescriptorVersion"
    },
    "0x7C06": {
        "data_type": "0x0003",
        "name": "RoamingDatatypes"
    },
    "0x7C07": {
        "data_type": "0x0102",
        "name": "RoamingDictionary"
    },
    "0x7C08": {
        "data_type": "0x0102",
        "name": "RoamingXmlStream"
    },
    "0x7C24": {
        "data_type": "0x000B",
        "name": "OscSyncEnabled"
    },
    "0x7D01": {
        "data_type": "0x000B",
        "name": "Processed"
    },
    "0x7FF9": {
        "data_type": "0x0040",
        "name": "ExceptionReplaceTime"
    },
    "0x7FFA": {
        "data_type": "0x0003",
        "name": "AttachmentLinkId"
    },
    "0x7FFB": {
        "data_type": "0x0040",
        "name": "ExceptionStartTime"
    },
    "0x7FFC": {
        "data_type": "0x0040",
        "name": "ExceptionEndTime"
    },
    "0x7FFD": {
        "data_type": "0x0003",
        "name": "AttachmentFlags"
    },
    "0x7FFE": {
        "data_type": "0x000B",
        "name": "AttachmentHidden"
    },
    "0x7FFF": {
        "data_type": "0x000B",
        "name": "AttachmentContactPhoto"
    },
    "0x8004": {
        "data_type": "0x001F",
        "name": "AddressBookFolderPathname"
    },
    "0x8005": {
        "data_type": "0x001F",
        "name": "AddressBookManagerDistinguishedName"
    },
    "0x8006": {
        "data_type": "0x001E",
        "name": "AddressBookHomeMessageDatabase"
    },
    "0x8008": {
        "data_type": "0x001E",
        "name": "AddressBookIsMemberOfDistributionList"
    },
    "0x8009": {
        "data_type": "0x000D",
        "name": "AddressBookMember"
    },
    "0x800C": {
        "data_type": "0x000D",
        "name": "AddressBookOwner"
    },
    "0x800E": {
        "data_type": "0x000D",
        "name": "AddressBookReports"
    },
    "0x800F": {
        "data_type": "0x101F",
        "name": "AddressBookProxyAddresses"
    },
    "0x8011": {
        "data_type": "0x001F",
        "name": "AddressBookTargetAddress"
    },
    "0x8015": {
        "data_type": "0x000D",
        "name": "AddressBookPublicDelegates"
    },
    "0x8024": {
        "data_type": "0x000D",
        "name": "AddressBookOwnerBackLink"
    },
    "0x802D": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute1"
    },
    "0x802E": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute2"
    },
    "0x802F": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute3"
    },
    "0x8030": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute4"
    },
    "0x8031": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute5"
    },
    "0x8032": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute6"
    },
    "0x8033": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute7"
    },
    "0x8034": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute8"
    },
    "0x8035": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute9"
    },
    "0x8036": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute10"
    },
    "0x803C": {
        "data_type": "0x001F",
        "name": "AddressBookObjectDistinguishedName"
    },
    "0x806A": {
        "data_type": "0x0003",
        "name": "AddressBookDeliveryContentLength"
    },
    "0x8073": {
        "data_type": "0x000D",
        "name": "AddressBookDistributionListMemberSubmitAccepted"
    },
    "0x8170": {
        "data_type": "0x101F",
        "name": "AddressBookNetworkAddress"
    },
    "0x8C57": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute11"
    },
    "0x8C58": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute12"
    },
    "0x8C59": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute13"
    },
    "0x8C60": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute14"
    },
    "0x8C61": {
        "data_type": "0x001F",
        "name": "AddressBookExtensionAttribute15"
    },
    "0x8C6A": {
        "data_type": "0x1102",
        "name": "AddressBookX509Certificate"
    },
    "0x8C6D": {
        "data_type": "0x0102",
        "name": "AddressBookObjectGuid"
    },
    "0x8C8E": {
        "data_type": "0x001F",
        "name": "AddressBookPhoneticGivenName"
    },
    "0x8C8F": {
        "data_type": "0x001F",
        "name": "AddressBookPhoneticSurname"
    },
    "0x8C90": {
        "data_type": "0x001F",
        "name": "AddressBookPhoneticDepartmentName"
    },
    "0x8C91": {
        "data_type": "0x001F",
        "name": "AddressBookPhoneticCompanyName"
    },
    "0x8C92": {
        "data_type": "0x001F",
        "name": "AddressBookPhoneticDisplayName"
    },
    "0x8C93": {
        "data_type": "0x0003",
        "name": "AddressBookDisplayTypeExtended"
    },
    "0x8C94": {
        "data_type": "0x000D",
        "name": "AddressBookHierarchicalShowInDepartments"
    },
    "0x8C96": {
        "data_type": "0x101F",
        "name": "AddressBookRoomContainers"
    },
    "0x8C97": {
        "data_type": "0x000D",
        "name": "AddressBookHierarchicalDepartmentMembers"
    },
    "0x8C98": {
        "data_type": "0x001E",
        "name": "AddressBookHierarchicalRootDepartment"
    },
    "0x8C99": {
        "data_type": "0x000D",
        "name": "AddressBookHierarchicalParentDepartment"
    },
    "0x8C9A": {
        "data_type": "0x000D",
        "name": "AddressBookHierarchicalChildDepartments"
    },
    "0x8C9E": {
        "data_type": "0x0102",
        "name": "ThumbnailPhoto"
    },
    "0x8CA0": {
        "data_type": "0x0003",
        "name": "AddressBookSeniorityIndex"
    },
    "0x8CA8": {
        "data_type": "0x001F",
        "name": "AddressBookOrganizationalUnitRootDistinguishedName"
    },
    "0x8CAC": {
        "data_type": "0x101F",
        "name": "AddressBookSenderHintTranslations"
    },
    "0x8CB5": {
        "data_type": "0x000B",
        "name": "AddressBookModerationEnabled"
    },
    "0x8CC2": {
        "data_type": "0x0102",
        "name": "SpokenName"
    },
    "0x8CD8": {
        "data_type": "0x000D",
        "name": "AddressBookAuthorizedSenders"
    },
    "0x8CD9": {
        "data_type": "0x000D",
        "name": "AddressBookUnauthorizedSenders"
    },
    "0x8CDA": {
        "data_type": "0x000D",
        "name": "AddressBookDistributionListMemberSubmitRejected"
    },
    "0x8CDB": {
        "data_type": "0x000D",
        "name": "AddressBookDistributionListRejectMessagesFromDLMembers"
    },
    "0x8CDD": {
        "data_type": "0x000B",
        "name": "AddressBookHierarchicalIsHierarchicalGroup"
    },
    "0x8CE2": {
        "data_type": "0x0003",
        "name": "AddressBookDistributionListMemberCount"
    },
    "0x8CE3": {
        "data_type": "0x0003",
        "name": "AddressBookDistributionListExternalMemberCount"
    },
    "0xFFFB": {
        "data_type": "0x000B",
        "name": "AddressBookIsMaster"
    },
    "0xFFFC": {
        "data_type": "0x0102",
        "name": "AddressBookParentEntryId"
    },
    "0xFFFD": {
        "data_type": "0x0003",
        "name": "AddressBookContainerId"
    }
}

KNOWN_MIME_TYPE = ['composite document file v2 document', 'cdfv2 microsoft outlook message',
                   'MIME entity, ISO-8859 text', 'data', 'apple hfs', 'macintosh hfs', 'rfc 822 mail', 'smtp mail',
                   'multipart/signed', 'multipart/alternative', 'multipart/mixed', 'message/rfc822',
                   'application/pkcs7-mime', 'multipart/related', '(with bom) text', 'ascii text', 'unicode text']
