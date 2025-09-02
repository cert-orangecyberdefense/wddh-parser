"""
Files containing class representing each section of the Windows Defender detection history files
"""

import collections
import json
import logging
from abc import ABC
from typing import TYPE_CHECKING, BinaryIO

from wddh.ltv_reader import (
    BlobEntry,
    FiletimeEntry,
    ProbablyBoolEntry,
    S32Entry,
    U32Entry,
    U64Entry,
    UuidEntry,
    WStrEntry,
)
from wddh.mp_threat_dectection_enum import ThreatStatusID

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class WDDHPart(collections.abc.Mapping, ABC):
    def __repr__(self):
        return json.dumps(self.__dict__, default=str)

    def keys(self):
        return list(self.__dict__.keys())

    def __getitem__(self, key):
        return self.__dict__[key]

    def __iter__(self):
        yield from self.__dict__.items()

    def __len__(self):
        return len(self.__dict__)


class WDDHHeader(WDDHPart):
    def __init__(self, fh: BinaryIO, offset: int = 0):
        fh = fh
        if offset:
            fh.seek(offset)
        self.threat_id = U64Entry(fh).as_u64
        self.detection_id = UuidEntry(fh).as_uuid
        magic_or_threat_name = WStrEntry(fh).as_str
        # Magic version is missing in some old samples

        if magic_or_threat_name.lower().startswith("magic.version"):
            self.magic_version = magic_or_threat_name
            self.threat_name = WStrEntry(fh).as_str
        else:
            logger.info(
                "No magic in header",
            )
            self.threat_name = magic_or_threat_name
            self.magic_version = None


class WDDHFlags(WDDHPart):
    def __init__(self, fh: BinaryIO, offset: int = 0):
        fh = fh
        if offset:
            fh.seek(offset)

        # This flag is used to assert present of a section
        self.flag_1 = U32Entry(fh).as_u32
        self.flag_2 = U32Entry(fh).as_u32
        self.flag_3 = U32Entry(fh).as_u32
        self.flag_4 = U32Entry(fh).as_u32
        self.flag_5 = U32Entry(fh).as_u32
        self.threat_status_id = ThreatStatusID(U32Entry(fh).as_u32)
        self.flag_list_len = U32Entry(fh).as_u32
        self.flag_list = []
        for i in range(self.flag_list_len):
            self.flag_list.append(U32Entry(fh).as_u32)
        self.alert_detail_count = U32Entry(fh).as_u32


class WDDHInformation(WDDHPart):
    def __init__(self, fh: BinaryIO, offset: int = 0):
        fh = fh
        if offset:
            fh.seek(offset)
        self.magic_version = WStrEntry(fh).as_str
        self.ressource_type = WStrEntry(fh).as_str
        self.ressource_location = WStrEntry(fh).as_str
        self.flag_1 = U32Entry(fh).as_u32
        self.blob_len = U32Entry(fh).as_u32
        self.blob = BlobEntry(fh)


class WDDHMetadata(WDDHPart):
    def __init__(self, fh: BinaryIO, offset: int = 0):
        fh = fh
        if offset:
            fh.seek(offset)
        self.last_threat_status_change = FiletimeEntry(fh)
        self.threat_status_error_code = S32Entry(fh).as_s32
        self.flag_1 = U32Entry(fh).as_u32
        self.unknown_uid = UuidEntry(fh).as_uuid
        self.current_threat_execution_id = U32Entry(fh).as_u32


class WDDHOptionalSection(WDDHPart):
    def __init__(self, fh: BinaryIO, offset: int = 0):
        fh = fh
        if offset:
            fh.seek(offset)
        raise NotImplementedError()


class WDDHMetadata2(WDDHPart):
    def __init__(self, fh: BinaryIO, offset: int = 0):
        if offset:
            fh.seek(offset)
        self.flag_1 = U32Entry(fh).as_u32
        self.domain_user = WStrEntry(fh).as_str
        self.flag_2 = U32Entry(fh).as_u32
        self.process_name = WStrEntry(fh).as_str
        self.flag_3 = U32Entry(fh).as_u32
        self.flag_4 = U32Entry(fh).as_u32
        self.flag_5 = U32Entry(fh).as_u32
        self.initial_detection_time = FiletimeEntry(fh)
        self.flag_6 = U32Entry(fh).as_u32
        self.remediation = FiletimeEntry(fh)
        self.flag_7 = U32Entry(fh).as_u32
        self.unknown_1 = ProbablyBoolEntry(fh)
        self.flag_8 = U32Entry(fh).as_u32
        self.domain_user_group = WStrEntry(fh).as_str  # unsure
        self.flag_9 = U32Entry(fh).as_u32
        self.count_following_information_section = U32Entry(fh).as_u32


class WDDHFooter(WDDHPart):
    def __init__(self, fh: BinaryIO, offset: int = 0):
        if offset:
            fh.seek(offset)
        self.unknown_1 = ProbablyBoolEntry(fh)
        self.flag_1 = U32Entry(fh).as_u32
        self.flag_2 = U32Entry(fh).as_u32
        self.flag_3 = U32Entry(fh).as_u32
        self.flag_4 = U32Entry(fh).as_u32
