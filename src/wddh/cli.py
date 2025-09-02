#!/usr/bin/env python3
import argparse
import collections
import io
import json
import logging
import sys
from importlib.metadata import version
from pathlib import Path
from typing import BinaryIO

from wddh.wddh_clean import WDDHClean

logger = logging.getLogger(__name__)


def gen_argparse() -> argparse.ArgumentParser:
    """

    :return:
    """
    parser = argparse.ArgumentParser(
        description="Parser for Windows Defender Detection history (files located under \ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\)"
    )
    # * pour plusieur fichier
    parser.add_argument(
        "-i",
        "--in",
        required=False,
        type=argparse.FileType("rb"),
        help="Input file",
        dest="infile",
    )
    parser.add_argument(
        "-D",
        "--directory",
        required=False,
        type=Path,
        help="Input directory",
        dest="directory",
    )
    parser.add_argument(
        "-s", "--short", action="store_true", help="Only return a subset of information"
    )
    parser.add_argument(
        "-o",
        "--out",
        nargs="?",
        type=argparse.FileType("w"),
        dest="outfile",
        default=sys.stdout,
    )
    parser.add_argument(
        "-d",
        "--debug",
        help="Logs in debug mode (DEBUG)",
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
        default=logging.WARNING,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Logs in verbose mode (INFO)",
        action="store_const",
        dest="loglevel",
        const=logging.INFO,
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s  {version('wddh')}"
    )
    return parser


def custom_json(obj):
    if isinstance(obj, collections.abc.Mapping):
        return dict(obj)
    return str(obj)


def process_one_file(infile: BinaryIO):
    wddh = WDDHClean(infile)
    current_offset = infile.tell()
    infile.seek(0, io.SEEK_END)
    eof = infile.tell()
    infile.close()
    if eof != current_offset:
        logger.warning(
            "File not fully processed : %d read out of %d", current_offset, eof
        )
    return wddh


def dump_full(x: WDDHClean, outfile):
    json.dump(dict(x), outfile, default=custom_json)


def dump_short(x: WDDHClean, outfile):
    json.dump(x.as_short(), outfile, default=custom_json)


def main() -> int:
    args = gen_argparse().parse_args()
    logging.basicConfig(
        level=args.loglevel,
        format="[%(relativeCreated)dms]%(funcName)s:%(lineno)d | %(levelname)s - %(message)s",
    )

    infile = args.infile
    directory: Path = args.directory
    dump_func = dump_full
    if args.short:
        dump_func = dump_short
    if infile:
        dump_func(process_one_file(infile), args.outfile)
    if directory:
        ret = []
        if not directory.is_dir():
            logger.error("%s is not a directory, exit", directory)
            return 1
        for file in directory.rglob("*"):
            if file.is_file():
                with file.open("rb") as f:
                    try:
                        logger.debug("Processing file : %s", file)
                        ret.append(process_one_file(f))
                    except Exception as exc:
                        logger.warning("Fail to parse %s : %s", file, exc)
        ret.sort(key=lambda x: x.metadata_2.initial_detection_time.as_u64)
        for f in ret:
            dump_func(f, args.outfile)
            args.outfile.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
