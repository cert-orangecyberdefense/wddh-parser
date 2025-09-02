import logging
from functools import reduce
from typing import BinaryIO, Optional

from wddh.wddh_part import (
    WDDHFlags,
    WDDHFooter,
    WDDHHeader,
    WDDHInformation,
    WDDHMetadata,
    WDDHMetadata2,
    WDDHOptionalSection,
    WDDHPart,
)

logger = logging.getLogger(__name__)


class WDDHClean(WDDHPart):
    """
    THis class is used to parse a windows defender detection History in the cleaniest way possible and will fail if file is incomplete or corrupted
    """

    def __init__(self, fh: BinaryIO, offset: Optional[int] = None):
        if offset:
            fh.seek(offset)
        logger.debug("Processing header at offset 0x%x", fh.tell())
        self.header = WDDHHeader(fh)
        logger.debug("Processing flags at offset 0x%x", fh.tell())
        self.flag_section = WDDHFlags(fh)
        self.alert_details = []
        for _ in range(self.flag_section.alert_detail_count):
            self.alert_details.append(WDDHInformation(fh))
        self.metadata = WDDHMetadata(fh)
        self.optional = None
        if self.flag_section.flag_1 == 4:
            self.optional = WDDHOptionalSection(fh)
        self.metadata_2 = WDDHMetadata2(fh)
        self.alert_details_2 = []
        for _ in range(self.metadata_2.count_following_information_section):
            self.alert_details_2.append(WDDHInformation(fh))
        self.footer = WDDHFooter(fh)

    def __repr__(self):
        return str(self.__dict__)

    def as_short(self) -> dict:
        """

        Returns: Only essential information, as dict

        """
        return {
            "threat_id": self.header.threat_id,
            "threat_name": self.header.threat_name,
            "threat_status": self.flag_section.threat_status_id.name,
            "domain_user": self.metadata_2.domain_user,
            "domain_user_group": self.metadata_2.domain_user_group,
            "process_name": self.metadata_2.process_name,
            "initial_detection_time": self.metadata_2.initial_detection_time,
            "remediation": self.metadata_2.remediation,
            "ressources": [
                f"{r.ressource_type} {r.ressource_location}" for r in self.alert_details
            ],
            "misc": reduce(
                lambda a, b: dict(a, **b), list(x.blob for x in self.alert_details), {}
            ),
        }
