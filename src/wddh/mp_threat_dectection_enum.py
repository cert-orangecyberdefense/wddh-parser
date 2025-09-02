"""
Enum from https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpthreatdetection



"""

from enum import Enum


class ThreatStatusID(Enum):
    Unknown = 0
    Detected = 1
    Cleaned = 2
    Quarantined = 3
    Removed = 4
    Allowed = 5
    Blocked = 6  # CleanFailed
    QuarantineFailed = 102
    RemoveFailed = 103
    AllowFailed = 104
    Abondoned = 105  # typo from documentation
    BlockedFailed = 107
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
