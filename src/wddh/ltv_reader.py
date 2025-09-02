"""
Files containing type containing each section
"""

import collections
import io
import json
import logging
import struct
import uuid
from enum import Enum
from typing import BinaryIO, Optional, Any

from wddh.utils import windows_timestamp_to_datetime

logger = logging.getLogger(__name__)


def strip_trailing_0_byte_wstr(b: bytes) -> bytes:
    if b.endswith(b"\x00\x00"):
        return b[:-2]
    else:
        return b


class TLVTypeEnum(Enum):
    UNKNOWN_0 = 0x0  # Maybe bool?
    UNKNOWN_1 = 0x1  # Only found in Blob
    SINT32 = 0x05
    UINT32 = 0x06
    UINT64 = 0x08
    FILETIME = 0x0A
    WSTRING = 0x15
    UUID = 0x1E
    BLOB = 0x28
    MISSING = -1

    @classmethod
    def _missing_(cls, value):
        """
        Set default value to prevent crash is value is missing
        Args:
            value:

        Returns:

        """
        return cls.MISSING


class LTVEntry:
    """
    Represent a Length Type Value entry
    """

    def __init__(
        self,
        fh: BinaryIO,
        expected_type: Optional[TLVTypeEnum] = None,
        expected_len: Optional[int] = None,
    ):
        """
        Create a TLV entry from a BinaryIO stream
        read empty byte after data in order to have an 8 bytes alignement
        log an info is type is not expected type

        Args:
            fh:
            expected_type:
            expected_len:
        """
        self.size: int = struct.unpack("<l", fh.read(4))[0]
        self.type_as_int = struct.unpack("<l", fh.read(4))[0]
        self.type: TLVTypeEnum = TLVTypeEnum(self.type_as_int)
        if expected_type and self.type != expected_type:
            logger.warning(
                "Do not find expected type at offset 0x%x. Expected : %s, Found : %s",
                fh.tell() - 4,
                expected_type,
                self.type,
            )
        self.raw_data: bytes = fh.read(self.size)
        # 8 byte alignement for the whole struct is expected
        padding = self.size % 8
        if padding:
            fh.read(8 - padding)

    def __repr__(self):
        return f"<L:{self.size}|T:{self.type_as_int}|V:{self.raw_data}>"


class U64Entry(LTVEntry):
    def __init__(self, fh: BinaryIO):
        super().__init__(fh, expected_type=TLVTypeEnum.UINT64, expected_len=8)
        self.as_u64 = struct.unpack("<Q", self.raw_data)[0]


class U32Entry(LTVEntry):
    def __init__(self, fh: BinaryIO):
        super().__init__(fh, expected_type=TLVTypeEnum.UINT32, expected_len=4)
        self.as_u32 = struct.unpack("<L", self.raw_data)[0]


class S32Entry(LTVEntry):
    """
    Signed 32 bytes
    """

    def __init__(self, fh: BinaryIO):
        super().__init__(fh, expected_type=TLVTypeEnum.SINT32, expected_len=4)
        self.as_s32 = struct.unpack("<l", self.raw_data)[0]


class UuidEntry(LTVEntry):
    def __init__(self, fh: BinaryIO):
        super().__init__(fh, expected_type=TLVTypeEnum.UUID, expected_len=0x10)
        self.as_uuid = str(uuid.UUID(bytes_le=self.raw_data))


class WStrEntry(LTVEntry):
    def __init__(self, fh: BinaryIO, errors="backslashreplace"):
        """

        Args:
            fh:
            errors: decoding errors handling mode (backslashreplace, errors etc...)
        """
        super().__init__(fh, expected_type=TLVTypeEnum.WSTRING)

        self.as_str = self.raw_data.decode("utf16", errors=errors)
        if self.as_str.endswith("\x00"):
            self.as_str = self.as_str[:-1]


class FiletimeEntry(LTVEntry):
    """
    Represent en windows filetime entry

    References:
        https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
    """

    def __init__(self, fh: BinaryIO):
        super().__init__(fh, expected_type=TLVTypeEnum.FILETIME, expected_len=8)
        self.as_u64 = struct.unpack("<Q", self.raw_data)[0]
        self.as_datetime = windows_timestamp_to_datetime(float(self.as_u64))

    def __str__(self):
        return self.as_datetime.isoformat()


class ProbablyBoolEntry(LTVEntry):
    def __init__(self, fh: BinaryIO):
        super().__init__(fh, expected_type=TLVTypeEnum.UNKNOWN_0, expected_len=4)
        self.as_u32 = struct.unpack("<L", self.raw_data)[0]


class BlobEnumType(Enum):
    UINT32 = 0x03  # Bool
    INT64 = 0x04  # time or int?
    BOOL = 0x05  # time or int?
    WSTRING = 0x06
    STRING = 0x07  # ASCII string


class BlobEntry(LTVEntry, collections.abc.Mapping):
    def __init__(self, fh: BinaryIO, errors="backslashreplace"):
        """

        Args:
            fh:
            errors: decoding errors handling mode (backslashreplace, errors etc...)
        """
        fh_start = fh.tell()
        super().__init__(fh, expected_type=TLVTypeEnum.BLOB)
        section_fh = io.BytesIO(self.raw_data)

        self.blob_map: dict[str, str | int | bool] = {}
        # May be empty
        if self.size == 0:
            return
        unknown_section = struct.unpack(
            "<l", section_fh.read(0x04)
        )[
            0
        ]  # These byte seems to contain unused information like repetition of blob length,
        # Look like a specific type
        if unknown_section == self.size:
            # first 0x04 byte are the blob length
            # Only found in the same samples were magic were absent from header
            pass
        else:
            # On most sample, 0x18 byte section with unknown information
            section_fh.read(0x14)
        while section_fh.tell() < self.size:
            value_type_int = None
            try:
                readable_key, value = self.read_key_val_entry(section_fh)
                if readable_key in self.blob_map:
                    logger.warning(
                        "Key already existing : %s, overriding previous key",
                        readable_key,
                    )
                self.blob_map[readable_key] = value
                value_type_int = None
            except struct.error:
                logger.warning(
                    "Fail to fully parse blob starting at offset 0x%x, current offset : 0x%x. Type : %s. Blob length :%d",
                    fh_start,
                    fh_start + section_fh.tell(),
                    value_type_int,
                    self.size,
                )

    def read_key_val_entry(self, section_fh) -> tuple[str, Any]:
        """
        Blob is made of kind of a key value list
        :param section_fh:
        :return: [key, value]
        """

        readable_key = self.read_w_str(section_fh)
        value_type_int = self.read_uint32(section_fh)
        logger.debug(
            "[BLOB]Reading for type %s for key %s", value_type_int, readable_key
        )

        match value_type_int:
            case BlobEnumType.WSTRING.value:
                return readable_key, self.read_w_str(section_fh)
            case BlobEnumType.UINT32.value:
                return readable_key, self.read_uint32(section_fh)
            case BlobEnumType.BOOL.value:
                content = section_fh.read(1)
                return readable_key, struct.unpack("?", content)[0]
            case BlobEnumType.INT64.value:
                content = section_fh.read(8)
                return readable_key, struct.unpack("<Q", content)[0]
            case BlobEnumType.STRING.value:
                return readable_key, self.read_str(section_fh)
            case _:
                logger.info(
                    "unknown blog blob TLV type : %d, will probably trying to process it as a string",
                    value_type_int,
                )
                return readable_key, self.read_w_str(section_fh)

    def __repr__(self):
        return json.dumps(self.blob_map)

    def read_w_str(self, section_fh: BinaryIO) -> str:
        value_len = self.read(section_fh, 4, "<L")
        content = strip_trailing_0_byte_wstr(section_fh.read(value_len))
        return content.decode("utf-16", errors="backslashreplace")

    def read_str(self, section_fh: BinaryIO) -> str:
        value_len = self.read(section_fh, 4, "<L")
        content = strip_trailing_0_byte_wstr(section_fh.read(value_len))
        return content.decode("ascii", errors="backslashreplace")

    def read_uint32(self, section_fh: BinaryIO) -> int:
        return self.read(section_fh, 4, "<L")

    def read_uint64(self, section_fh: BinaryIO) -> int:
        return self.read(section_fh, 8, "<Q")

    def read_bool(self, section_fh: BinaryIO) -> int:
        _ = section_fh.read(1)
        return self.read(section_fh, 1, "<?")

    def read(self, section_fh: BinaryIO, size: int, struct_fmt: str):
        """
        Read size byte from section fh and return first part of the unpacked struct using struct_fmt
        Args:
            section_fh:
            size:
            struct_fmt:

        Returns:

        """
        content = section_fh.read(size)  # todo ensure readed size == expected size
        return struct.unpack(struct_fmt, content)[0]

    def __getitem__(self, key):
        return self.blob_map[key]

    def __iter__(self):
        yield from self.blob_map.items()

    def __len__(self):
        return len(self.blob_map)

    def keys(self):
        return list(self.blob_map.keys())
