import datetime
import io
import logging
from typing import BinaryIO

from wddh.ltv_reader import TLVTypeEnum
from wddh.mp_threat_dectection_enum import ThreatStatusID
from wddh.wddh_clean import WDDHClean
from wddh.wddh_part import (
    WDDHHeader,
    WDDHFlags,
    WDDHInformation,
    WDDHMetadata,
    WDDHFooter,
    WDDHMetadata2,
)


def test_mimikatz_header(wddh_mimikatz: BinaryIO):
    wddh = WDDHHeader(wddh_mimikatz)
    assert wddh.threat_id == 2147686744
    assert wddh.detection_id.lower() == "94BBE9CF-CDEB-4885-9178-CC93FB10822D".lower()
    assert wddh.magic_version == "Magic.Version:1.2"
    assert wddh.threat_name == "HackTool:Win32/Mimikatz"
    assert wddh_mimikatz.tell() == 0x90


def test_mimikatz_flags(wddh_mimikatz: BinaryIO):
    wddh = WDDHFlags(wddh_mimikatz, offset=0x90)
    assert wddh.alert_detail_count == 1
    assert wddh.threat_status_id == ThreatStatusID.Quarantined
    assert wddh_mimikatz.tell() == 320


def test_mimikatz_information(wddh_mimikatz: BinaryIO):
    wddh = WDDHInformation(wddh_mimikatz, offset=0x140)
    assert wddh.magic_version == "Magic.Version:1.2"
    assert wddh.ressource_type == "file"
    assert wddh.ressource_location == "C:\\Users\\RaptorSniper\\Downloads\\a.zip"
    assert wddh_mimikatz.tell() == 0x718


def test_mimikatz_metadata(wddh_mimikatz: BinaryIO):
    wddh = WDDHMetadata(wddh_mimikatz, offset=0x718)
    assert wddh.last_threat_status_change.as_datetime == datetime.datetime(
        2025, 1, 28, 16, 45, 6, 220888, tzinfo=datetime.timezone.utc
    )
    assert wddh_mimikatz.tell() == 0x770


def test_mimikatz_metadata_2(wddh_mimikatz: BinaryIO):
    _ = WDDHMetadata2(wddh_mimikatz, offset=0x770)
    assert wddh_mimikatz.tell() == 0x938


def test_mimikatz_footer(wddh_mimikatz: BinaryIO):
    wddh = WDDHFooter(wddh_mimikatz, offset=0x938)
    current_offset = wddh_mimikatz.tell()
    _ = wddh_mimikatz.seek(0, io.SEEK_END)
    assert wddh.unknown_1.type == TLVTypeEnum.UNKNOWN_0
    assert wddh_mimikatz.tell() == current_offset


def test_no_info_dfir_museum_files(wddh_dfir_museum: BinaryIO, caplog):
    with caplog.at_level(logging.INFO, logger="wddh"):
        _ = WDDHClean(wddh_dfir_museum)
        assert len(caplog.records) == 0
