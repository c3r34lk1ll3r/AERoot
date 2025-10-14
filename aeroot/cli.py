"""
AERoot CLI module (Entry Point)
"""

import argparse
import sys

from aeroot import __version__
from aeroot.aeroot import AERoot, Mode, ProcessNotRunningError, AERootError
from aeroot.util import Logger, error, info, title, EXIT_ERR
from aeroot import mem_scraper

def handle_cmd_line() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AERoot (Android Emulator ROOTing system) v. {}".format(__version__)
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--verbose", "-v", action="store_true", help="show debug level messages"
    )
    group.add_argument("--quiet", "-q", action="store_true", help="quiet output")
    parser.add_argument(
        "--device", "-d", default="emulator-5554", help="specify the device name"
    )
    parser.add_argument("--host", default="127.0.0.1", help="specify adb host")
    parser.add_argument("--port", "-p", type=int, default=5037, help="specify adb port")
    parser.add_argument("--mem_scrape", help="try to detect offset using heuristic and create yaml file")
    # Mode [pid|name|daemon]
    subparsers = parser.add_subparsers()

    # Search by name mode
    name = subparsers.add_parser(
        "name", help="find a process by name and overwrite credentials"
    )
    name.add_argument("process_name", help="the process name")
    name.set_defaults(mode=Mode.NAME)

    # Search by pid mode
    pid = subparsers.add_parser(
        "pid", help="find a process by PID and overwrite credentials"
    )
    pid.add_argument("pid", type=int, help="the process PID")
    pid.set_defaults(mode=Mode.PID)

    # Daemon mode
    daemon = subparsers.add_parser("daemon", help="overwrite adb daemon credentials")
    daemon.set_defaults(process_name="adbd")
    daemon.set_defaults(mode=Mode.NAME)

    config = parser.parse_args()

    if not hasattr(config, "pid") and not hasattr(config, "process_name"):
        config.process_name = "adbd"
        config.mode = Mode.NAME

    return config


def main():
    options = handle_cmd_line()
    Logger.init(options)

    title("AERoot (Android Emulator ROOTing system) v. {}".format(__version__))
    
    if options.mem_scrape != None:
        mem_scraper.forensic(options)
        return
    aeroot = AERoot(options)
    try:
        aeroot.do_root()
    except AERootError as err:
        error(f"{err} **Aborting**")
    except ProcessNotRunningError:
        error("Process is not running. **Aborting**")
    except RuntimeError as err:
        error(f"{err} **Aborting**")
    finally:
        try:
            aeroot.cleanup()
        except RuntimeError:
            pass
        info("Exiting")
