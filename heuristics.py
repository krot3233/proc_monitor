import json
import os
import subprocess

import psutil

from config import (
    BAD_DIRS,
    WEIGHT_BAD_PATH,
    WEIGHT_BAD_CMDLINE,
    WEIGHT_INJECTION_SUSPICIOUS_DLL,
    WEIGHT_MASQUERADING,
    WEIGHT_OFFICE_SPAWNS_SHELL,
    WEIGHT_UNSIGNED,
)

# Тут получаем папку Windows из переменных среды.
WINDOWS_DIR = os.environ.get("WINDIR") or os.environ.get("SystemRoot", "")
if WINDOWS_DIR:
    WINDOWS_DIR = os.path.normpath(WINDOWS_DIR)
SYSTEM32_DIR = os.path.join(WINDOWS_DIR, "System32") if WINDOWS_DIR else ""

SYSTEM_PATHS = {}
if WINDOWS_DIR:
    SYSTEM_PATHS = {
        "svchost.exe": SYSTEM32_DIR,
        "lsass.exe": SYSTEM32_DIR,
        "csrss.exe": SYSTEM32_DIR,
        "explorer.exe": WINDOWS_DIR,
    }

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
BAD_CMD = [
    "downloadstring",
    "urlcache",
    "bitsadmin",
    "frombase64string",
]


# Тут проверяем, не запущен ли процесс из временной или пользовательской папки.
def is_bad_path(info):
    if not info.exe:
        return False, 0, "bad_path"

    path = os.path.normcase(info.exe).lower()

    for bad_dir in BAD_DIRS:
        if bad_dir in path:
            return True, WEIGHT_BAD_PATH, "bad_path"

    return False, 0, "bad_path"


# Тут сверяем системные программы с их обычной папкой Windows.
def is_masquerading(info):
    expected = SYSTEM_PATHS.get(info.name.lower())
    if expected and info.exe:
        path = os.path.normcase(info.exe).lower()
        expected = os.path.normcase(expected).lower()
        if path != expected and not path.startswith(expected + os.sep):
            return True, WEIGHT_MASQUERADING, "masquerading"
    return False, 0, "masquerading"


# Тут проверяем, что Office не запускает командную оболочку.
def is_bad_parent_child(info):
    if (
        info.parent_name.lower() in OFFICE
        and info.name.lower() in SHELLS
    ):
        return True, WEIGHT_OFFICE_SPAWNS_SHELL, "office_spawns_shell"
    return False, 0, "office_spawns_shell"


# Тут ищем подозрительные параметры PowerShell и другие команды.
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


# Тут PowerShell Windows проверяет, действительна ли подпись файла.
def _get_signature_statuses(paths):
    if not paths:
        return []
    if not WINDOWS_DIR:
        print("[SIGNATURE_ERROR] Не удалось определить папку Windows.")
        return None

    powershell = os.path.join(
        WINDOWS_DIR,
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
    )
    script = (
        "$paths = [Console]::In.ReadToEnd() | ConvertFrom-Json; "
        "$results = foreach ($path in $paths) { "
        "try { "
        "$signature = Get-AuthenticodeSignature "
        "-LiteralPath $path -ErrorAction Stop; "
        "[PSCustomObject]@{Path=$path; Status=$signature.Status.ToString()} "
        "} catch { "
        "[PSCustomObject]@{Path=$path; Status='Error'; "
        "Message=$_.Exception.Message} "
        "} "
        "}; "
        "ConvertTo-Json -InputObject @($results) -Compress"
    )

    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            input=json.dumps(paths),
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        print("[SIGNATURE_ERROR] Проверка подписей превысила лимит 15 секунд.")
        return None
    except OSError as error:
        print(f"[SIGNATURE_ERROR] Не удалось запустить проверку подписей: {error}")
        return None

    if result.returncode != 0:
        error = result.stderr.strip() or "PowerShell завершился с ошибкой."
        print(f"[SIGNATURE_ERROR] Не удалось проверить подписи: {error}")
        return None

    try:
        statuses = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        print(f"[SIGNATURE_ERROR] Не удалось разобрать результат проверки: {error}")
        return None

    if isinstance(statuses, dict):
        statuses = [statuses]
    return statuses


def check_signature(info):
    if not info.exe:
        return False, 0, "unsigned"

    statuses = _get_signature_statuses([info.exe])
    if not statuses:
        return False, 0, "unsigned"

    status = statuses[0]
    if status["Status"] == "Error":
        print(
            "[SIGNATURE_ERROR] Не удалось проверить подпись:",
            status.get("Path", info.exe),
            status.get("Message", ""),
        )
        return False, 0, "unsigned"
    if status["Status"] != "Valid":
        return True, WEIGHT_UNSIGNED, "unsigned"
    return False, 0, "unsigned"


# Тут ищем загруженные DLL из подозрительных папок или без действительной подписи.
def is_suspicious_dlls(info):
    try:
        memory_maps = psutil.Process(info.pid).memory_maps()
    except psutil.AccessDenied:
        print("[DLL_SCAN_ERROR] Нет доступа к списку библиотек процесса:", info.pid)
        return False, 0, "suspicious_dll_injection"
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return False, 0, "suspicious_dll_injection"

    suspicious_dirs = []
    for variable in ("TEMP", "TMP", "APPDATA", "LOCALAPPDATA"):
        directory = os.environ.get(variable)
        if directory:
            directory = os.path.normcase(os.path.abspath(directory)).lower()
            suspicious_dirs.append(directory.rstrip(os.sep) + os.sep)

    dll_paths = []
    for memory_map in memory_maps:
        path = memory_map.path
        if not path or os.path.splitext(path)[1].lower() != ".dll":
            continue

        dll_path = os.path.normcase(os.path.abspath(path)).lower()
        for directory in suspicious_dirs:
            if dll_path.startswith(directory):
                return True, WEIGHT_INJECTION_SUSPICIOUS_DLL, "suspicious_dll_injection"

        dll_paths.append(path)

    statuses = _get_signature_statuses(dll_paths)
    if statuses is None:
        return False, 0, "suspicious_dll_injection"

    for status in statuses:
        if status["Status"] == "Error":
            print(
                "[SIGNATURE_ERROR] Не удалось проверить подпись DLL:",
                status.get("Path", ""),
                status.get("Message", ""),
            )
        elif status["Status"] != "Valid":
            return True, WEIGHT_INJECTION_SUSPICIOUS_DLL, "suspicious_dll_injection"

    return False, 0, "suspicious_dll_injection"


RULES = [
    is_bad_path,
    is_masquerading,
    is_bad_parent_child,
    is_bad_cmdline,
    is_suspicious_dlls,
]
