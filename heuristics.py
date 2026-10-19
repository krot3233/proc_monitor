import os

from config import (
    BAD_DIRS,
    WEIGHT_BAD_PATH,
    WEIGHT_BAD_CMDLINE,
    WEIGHT_MASQUERADING,
    WEIGHT_OFFICE_SPAWNS_SHELL,
)


SYSTEM_PATHS = {
    "svchost.exe": r"c:\windows\system32",
    "lsass.exe": r"c:\windows\system32",
    "csrss.exe": r"c:\windows\system32",
    "explorer.exe": r"c:\windows",
}

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
BAD_CMD = [
    "downloadstring",
    "urlcache",
    "bitsadmin",
    "frombase64string",
]


def is_bad_path(info):
    if not info.exe:
        return False, 0, "bad_path"

    path = os.path.normcase(info.exe).lower()

    for bad_dir in BAD_DIRS:
        if bad_dir in path:
            return True, WEIGHT_BAD_PATH, "bad_path"

    return False, 0, "bad_path"


def is_masquerading(info):
    expected = SYSTEM_PATHS.get(info.name.lower())
    if expected and info.exe:
        path = os.path.normcase(info.exe).lower()
        expected = os.path.normcase(expected).lower()
        if path != expected and not path.startswith(expected + os.sep):
            return True, WEIGHT_MASQUERADING, "masquerading"
    return False, 0, "masquerading"


def is_bad_parent_child(info):
    if (
        info.parent_name.lower() in OFFICE
        and info.name.lower() in SHELLS
    ):
        return True, WEIGHT_OFFICE_SPAWNS_SHELL, "office_spawns_shell"
    return False, 0, "office_spawns_shell"


def is_bad_cmdline(info):
    args = [arg.lower() for arg in info.cmdline]
    hits = 0

    if "-enc" in args or "-encodedcommand" in args:
        hits += 1
    if "-nop" in args or "-noprofile" in args:
        hits += 1
    if "bypass" in args:
        hits += 1

    for index in range(len(args) - 1):
        if args[index] in {"-w", "-windowstyle"} and args[index + 1] == "hidden":
            hits += 1
            break

    for pattern in BAD_CMD:
        for arg in args:
            if pattern in arg:
                hits += 1
                break

    if hits:
        return True, WEIGHT_BAD_CMDLINE * hits, "bad_cmdline"
    return False, 0, "bad_cmdline"


RULES = [is_bad_path, is_masquerading, is_bad_parent_child, is_bad_cmdline]


