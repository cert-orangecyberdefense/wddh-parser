import datetime


def windows_timestamp_to_datetime(ts: float) -> datetime.datetime:
    """
    Windows timestamp conversion is bugged on windows : https://github.com/python/cpython/issues/81708
    format : https://devblogs.microsoft.com/oldnewthing/20090306-00/?p=18913

    :param ts: timestamp windows filetime 100-nanosecond intervals since January 1, 1601
    :return:
    """
    windows_epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    return windows_epoch + datetime.timedelta(microseconds=ts / 10)
