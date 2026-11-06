import json
import logging
import os
import subprocess
import threading
import time

import psutil

from config import (
    BAD_DIRS,
    WEIGHT_BAD_PATH,
    WEIGHT_BAD_CMDLINE,
    WEIGHT_INJECTION_SUSPICIOUS_DLL,
    WEIGHT_MASQUERADING,
    WEIGHT_OFFICE_SPAWNS_SHELL,
    WEIGHT_SIGNED_BAD_PATH,
    WEIGHT_SIGNED_LOLBIN_BAD_PATH,
    WEIGHT_UNSIGNED,
    WEIGHT_UNTRUSTED_DLL,
)

logger = logging.getLogger(__name__)
SIGNATURE_CACHE = {}
SIGNATURE_KEYS = {}
SIGNATURE_CACHE_LOCK = threading.Lock()
SIGNATURE_SCAN_LOCK = threading.Lock()
SIGNATURE_ERROR_LOGGED = set()
# Ошибка подписи кэшируется ненадолго: если файл станет доступен, проверка повторится.
SIGNATURE_ERROR_CACHE_TIME = 90.0
DLL_SCAN_CACHE = {}
# Не опрашиваем memory_maps чаще этого интервала для того же экземпляра процесса.
DLL_SCAN_CACHE_TIME = 90.0
DLL_SCAN_CACHE_LOCK = threading.Lock()
DLL_CACHE_PRUNED_AT = 0
DLL_ACCESS_DENIED_LOGGED = set()
DLL_ACCESS_DENIED_LOCK = threading.Lock()

# Системные пути берутся из установленной Windows, без привязки к диску C:.
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
        "services.exe": SYSTEM32_DIR,
        "winlogon.exe": SYSTEM32_DIR,
        "wininit.exe": SYSTEM32_DIR,
        "smss.exe": SYSTEM32_DIR,
        "lsm.exe": SYSTEM32_DIR,
        "taskhostw.exe": SYSTEM32_DIR,
        "spoolsv.exe": SYSTEM32_DIR,
        "explorer.exe": WINDOWS_DIR,
    }

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
LOLBINS = {
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wscript.exe",
    "cscript.exe",
    "bitsadmin.exe",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
}
BAD_CMD = [
    "downloadstring",
    "urlcache",
    "bitsadmin",
    "/transfer",
    "frombase64string",
]
# Для утилит с URL или скриптовыми обработчиками признаки весомее обычных.
LOLBIN_CMD = {
    "certutil.exe": (1, ("http://", "https://")),
    "bitsadmin.exe": (1, ("http://", "https://")),
    "regsvr32.exe": (1, ("http://", "https://", "scrobj.dll")),
    "mshta.exe": (2, ("http://", "https://", "javascript:", "vbscript:")),
    "rundll32.exe": (2, ("javascript:", "vbscript:")),
}


def log_signature_error_once(path, message):
    normalized_path = os.path.normcase(os.path.abspath(path)).lower()
    with SIGNATURE_CACHE_LOCK:
        if normalized_path in SIGNATURE_ERROR_LOGGED:
            return
        SIGNATURE_ERROR_LOGGED.add(normalized_path)
    logger.warning("[SIGNATURE_ERROR] %s: %s", message, path)


# Проверяем подозрительные каталоги отдельно: действительная подпись снижает оценку.
def is_bad_path(info):
    if not info.exe:
        return False, 0, "bad_path"

    path = os.path.normcase(info.exe).lower()

    for bad_dir in BAD_DIRS:
        try:
            if os.path.commonpath((path, bad_dir)) == bad_dir:
                statuses = _get_signature_statuses([info.exe])
                if not statuses or statuses[0]["Status"] == "Error":
                    log_signature_error_once(
                        info.exe,
                        "Не удалось проверить подозрительный путь",
                    )
                    return True, WEIGHT_BAD_PATH, "bad_path"
                if statuses[0]["Status"] == "Valid":
                    if info.name.lower() in LOLBINS:
                        return (
                            True,
                            WEIGHT_SIGNED_LOLBIN_BAD_PATH,
                            "signed_lolbin_bad_path",
                        )
                    return True, WEIGHT_SIGNED_BAD_PATH, "signed_bad_path"
                return True, WEIGHT_BAD_PATH, "bad_path"
        except ValueError:
            continue

    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        local_appdata = os.path.normcase(os.path.abspath(local_appdata)).lower()
        try:
            if os.path.commonpath((path, local_appdata)) == local_appdata:
                statuses = _get_signature_statuses([info.exe])
                if not statuses or statuses[0]["Status"] == "Error":
                    log_signature_error_once(
                        info.exe,
                        "Не удалось проверить подпись файла",
                    )
                    return True, WEIGHT_BAD_PATH, "bad_path"
                if statuses[0]["Status"] != "Valid":
                    return True, WEIGHT_BAD_PATH, "bad_path"
                return False, 0, "bad_path"
        except ValueError:
            pass

    return False, 0, "bad_path"


# Системные имена должны запускаться из своей штатной папки.
def is_masquerading(info):
    expected = SYSTEM_PATHS.get(info.name.lower())
    if expected and info.exe:
        path = os.path.normcase(os.path.dirname(info.exe)).lower()
        expected = os.path.normcase(expected).lower()
        if path != expected:
            return True, WEIGHT_MASQUERADING, "masquerading"
    return False, 0, "masquerading"


# Запуск оболочки из Office часто означает макрос или скрипт.
def is_bad_parent_child(info):
    if (
        info.parent_name.lower() in OFFICE
        and info.name.lower() in SHELLS
    ):
        return True, WEIGHT_OFFICE_SPAWNS_SHELL, "office_spawns_shell"
    return False, 0, "office_spawns_shell"


# Проверяем аргументы только у утилит, для которых эти шаблоны имеют смысл.
def is_bad_cmdline(info):
    process_name = info.name.lower()
    if process_name not in LOLBINS:
        return False, 0, "bad_cmdline"

    args = [arg.lower() for arg in info.cmdline]
    command_args = args[1:]
    hits = 0

    if process_name in {"powershell.exe", "pwsh.exe"}:
        # У PowerShell есть короткие варианты флага -EncodedCommand.
        encoded_flags = {"-e", "-ec", "-en"}
        for arg in args:
            if arg in encoded_flags or (
                len(arg) >= 4 and "-encodedcommand".startswith(arg)
            ):
                hits += 1
                break
        if any(arg == "-nop" or arg.startswith("-noprofile") for arg in args):
            hits += 1
        if "bypass" in args:
            hits += 1

        for index in range(len(args) - 1):
            if args[index] in {"-w", "-windowstyle"} and args[index + 1] == "hidden":
                hits += 1
                break

    for pattern in BAD_CMD:
        for arg in command_args:
            if pattern in arg:
                hits += 1
                break

    lolbin_rules = LOLBIN_CMD.get(process_name)
    if lolbin_rules:
        multiplier, patterns = lolbin_rules
        for pattern in patterns:
            for arg in command_args:
                if pattern in arg:
                    hits += multiplier
                    break

    if hits:
        return True, WEIGHT_BAD_CMDLINE * hits, "bad_cmdline"
    return False, 0, "bad_cmdline"


# PowerShell проверяет подписи пачками, чтобы не запускать отдельный процесс на каждый файл.
def _get_signature_statuses(paths):
    if not paths:
        return []

    statuses = []
    for start in range(0, len(paths), 40):
        batch = paths[start:start + 40]
        with SIGNATURE_SCAN_LOCK:
            batch_statuses = _get_signature_statuses_locked(batch)
        if batch_statuses is None:
            for path in batch:
                statuses.append({"Path": path, "Status": "Error"})
        else:
            statuses.extend(batch_statuses)
    return statuses


def _get_signature_statuses_locked(paths):
    if not paths:
        return []
    if not WINDOWS_DIR:
        logger.warning("[SIGNATURE_ERROR] Не удалось определить папку Windows.")
        return None

    powershell = os.path.join(
        WINDOWS_DIR,
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
    )
    script = (
        "[Console]::InputEncoding = [Text.Encoding]::UTF8; "
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
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

    # В кэше учитываются дата изменения и размер: после обновления файла проверка повторится.
    uncached_paths = []
    uncached_stat_keys = {}
    cached_statuses = {}
    now = time.monotonic()
    for path in paths:
        normalized_path = os.path.normcase(os.path.abspath(path)).lower()
        # Одна проверка PowerShell обслуживает сразу все пути из текущей пачки.
        try:
            file_stat = os.stat(path)
        except OSError:
            continue
        stat_key = (normalized_path, file_stat.st_mtime_ns, file_stat.st_size)
        # Подпись действительна только для конкретной версии файла на диске.
        with SIGNATURE_CACHE_LOCK:
            cached = SIGNATURE_CACHE.get(stat_key)
            if isinstance(cached, tuple):
                if now - cached[1] < SIGNATURE_ERROR_CACHE_TIME:
                    cached_statuses[normalized_path] = cached[0]
                else:
                    del SIGNATURE_CACHE[stat_key]
                    cached = None
        if cached is not None:
            if not isinstance(cached, tuple):
                cached_statuses[normalized_path] = cached
        elif path not in uncached_paths:
            uncached_paths.append(path)
            uncached_stat_keys[path] = stat_key

    if not uncached_paths:
        return [
            {"Path": path, "Status": cached_statuses.get(
                os.path.normcase(os.path.abspath(path)).lower(), "Error"
            )}
            for path in paths
        ]

    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            input=json.dumps(uncached_paths),
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        logger.warning("[SIGNATURE_ERROR] Проверка подписей превысила лимит 15 секунд.")
        for path in uncached_paths:
            _save_signature_status(path, "Error", uncached_stat_keys.get(path))
        return None
    except OSError as error:
        logger.warning("[SIGNATURE_ERROR] Не удалось запустить проверку подписей: %s", error)
        for path in uncached_paths:
            _save_signature_status(path, "Error", uncached_stat_keys.get(path))
        return None

    if result.returncode != 0:
        error = result.stderr.strip() or "PowerShell завершился с ошибкой."
        logger.warning("[SIGNATURE_ERROR] Не удалось проверить подписи: %s", error)
        for path in uncached_paths:
            _save_signature_status(path, "Error", uncached_stat_keys.get(path))
        return None

    try:
        statuses = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        logger.warning("[SIGNATURE_ERROR] Не удалось разобрать результат проверки: %s", error)
        for path in uncached_paths:
            _save_signature_status(path, "Error", uncached_stat_keys.get(path))
        return None

    if isinstance(statuses, dict):
        statuses = [statuses]
    status_by_path = {}
    for item in statuses:
        if not isinstance(item, dict) or not item.get("Path") or not item.get("Status"):
            logger.warning("[SIGNATURE_ERROR] PowerShell вернул неполные данные о подписи.")
            continue
        status_by_path[os.path.normcase(os.path.abspath(item["Path"])).lower()] = (
            item["Status"]
        )
    for path in uncached_paths:
        normalized_path = os.path.normcase(os.path.abspath(path)).lower()
        status = status_by_path.get(normalized_path)
        if status:
            _save_signature_status(path, status, uncached_stat_keys.get(path))
        else:
            _save_signature_status(path, "Error", uncached_stat_keys.get(path))
    cached_statuses.update(status_by_path)
    return [
        {
            "Path": path,
            "Status": cached_statuses.get(
                os.path.normcase(os.path.abspath(path)).lower(), "Error"
            ),
        }
        for path in paths
    ]


def _save_signature_status(path, status, expected_stat_key=None):
    normalized_path = os.path.normcase(os.path.abspath(path)).lower()
    try:
        file_stat = os.stat(path)
    except OSError:
        return
    stat_key = (normalized_path, file_stat.st_mtime_ns, file_stat.st_size)
    if expected_stat_key is not None and stat_key != expected_stat_key:
        return
    cache_value = status
    if status == "Error":
        cache_value = (status, time.monotonic())
    with SIGNATURE_CACHE_LOCK:
        # Удаляем запись старой версии файла, не перебирая весь кэш.
        old_key = SIGNATURE_KEYS.get(normalized_path)
        if old_key and old_key != stat_key:
            SIGNATURE_CACHE.pop(old_key, None)
        SIGNATURE_KEYS[normalized_path] = stat_key
        SIGNATURE_CACHE[stat_key] = cache_value


def check_signature(info):
    if not info.exe:
        return False, 0, "unsigned"

    statuses = _get_signature_statuses([info.exe])
    if not statuses:
        return False, 0, "unsigned"

    status = statuses[0]
    if status["Status"] == "Error":
        log_signature_error_once(
            status.get("Path", info.exe),
            status.get("Message", "Не удалось проверить подпись"),
        )
        return False, 0, "unsigned"
    if status["Status"] != "Valid":
        return True, WEIGHT_UNSIGNED, "unsigned"
    return False, 0, "unsigned"


# Ищем DLL вне доверенных каталогов; результат сканирования живет недолго в кэше.
def is_suspicious_dlls(info, check_signatures=False):
    global DLL_CACHE_PRUNED_AT

    cache_key = (info.pid, info.create_time)
    now = time.monotonic()
    with DLL_SCAN_CACHE_LOCK:
        if now - DLL_CACHE_PRUNED_AT >= 60 and len(DLL_SCAN_CACHE) > 1000:
            expired = []
            for key, value in DLL_SCAN_CACHE.items():
                if now - value[0] >= DLL_SCAN_CACHE_TIME * 2:
                    expired.append(key)
            for key in expired:
                del DLL_SCAN_CACHE[key]
            DLL_CACHE_PRUNED_AT = now
        cached = DLL_SCAN_CACHE.get(cache_key)
        if cached and now - cached[0] < DLL_SCAN_CACHE_TIME:
            return cached[1], cached[2], cached[3]

    try:
        memory_maps = psutil.Process(info.pid).memory_maps()
    except psutil.AccessDenied:
        with DLL_ACCESS_DENIED_LOCK:
            if info.pid not in DLL_ACCESS_DENIED_LOGGED:
                logger.warning(
                    "[DLL_SCAN_ERROR] Нет доступа к списку библиотек процесса: %s",
                    info.pid,
                )
                DLL_ACCESS_DENIED_LOGGED.add(info.pid)
        with DLL_SCAN_CACHE_LOCK:
            DLL_SCAN_CACHE[cache_key] = (now, False, 0, "suspicious_dll_injection")
        return False, 0, "suspicious_dll_injection"
    except OSError:
        logger.exception("[DLL_SCAN_ERROR] Ошибка чтения библиотек процесса %s", info.pid)
        with DLL_SCAN_CACHE_LOCK:
            DLL_SCAN_CACHE[cache_key] = (now, False, 0, "suspicious_dll_injection")
        return False, 0, "suspicious_dll_injection"
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return False, 0, "suspicious_dll_injection"

    dll_paths = []
    dll_in_bad_dir = {}
    trusted_dirs = []
    # Системные библиотеки и обычные установки не требуют проверки подписи по одной.
    for directory in (
        WINDOWS_DIR,
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("ProgramW6432"),
    ):
        if directory:
            trusted_dirs.append(os.path.normcase(os.path.abspath(directory)).lower())

    for memory_map in memory_maps:
        path = memory_map.path
        if not path or os.path.splitext(path)[1].lower() != ".dll":
            continue

        dll_path = os.path.normcase(os.path.abspath(path)).lower()
        trusted = False
        for directory in trusted_dirs:
            try:
                if os.path.commonpath((dll_path, directory)) == directory:
                    trusted = True
                    break
            except ValueError:
                continue
        if trusted:
            continue

        # Для остальных DLL важно, лежат ли они в каталоге, который часто используют вредоносы.
        in_bad_dir = False
        for directory in BAD_DIRS:
            try:
                if os.path.commonpath((dll_path, directory)) == directory:
                    in_bad_dir = True
                    break
            except ValueError:
                continue

        dll_in_bad_dir[path] = in_bad_dir
        dll_paths.append(path)

    if not check_signatures or not dll_paths:
        with DLL_SCAN_CACHE_LOCK:
            DLL_SCAN_CACHE[cache_key] = (now, False, 0, "suspicious_dll_injection")
        return False, 0, "suspicious_dll_injection"

    statuses = _get_signature_statuses(dll_paths)
    if statuses is None:
        logger.warning(
            "[DLL_SCAN_ERROR] Не удалось проверить подписи DLL процесса %s; результат неизвестен.",
            info.pid,
        )
        with DLL_SCAN_CACHE_LOCK:
            DLL_SCAN_CACHE[cache_key] = (now, False, 0, "suspicious_dll_injection")
        return False, 0, "suspicious_dll_injection"

    signature_errors = 0
    detected_weight = 0
    detected_rule = "suspicious_dll_injection"
    for status in statuses:
        if status["Status"] == "Error":
            signature_errors += 1
        elif status["Status"] != "Valid":
            if dll_in_bad_dir.get(status["Path"], False):
                detected_weight = WEIGHT_INJECTION_SUSPICIOUS_DLL
                detected_rule = "suspicious_dll_injection"
                break
            if detected_weight < WEIGHT_UNTRUSTED_DLL:
                detected_weight = WEIGHT_UNTRUSTED_DLL
                detected_rule = "unsigned_dll"

    if detected_weight:
        with DLL_SCAN_CACHE_LOCK:
            DLL_SCAN_CACHE[cache_key] = (now, True, detected_weight, detected_rule)
        return True, detected_weight, detected_rule

    if signature_errors:
        logger.warning(
                "[SIGNATURE_ERROR] Не удалось проверить подписи %s DLL процесса %s.",
                signature_errors,
                info.pid,
        )
    with DLL_SCAN_CACHE_LOCK:
        DLL_SCAN_CACHE[cache_key] = (now, False, 0, "suspicious_dll_injection")
    return False, 0, "suspicious_dll_injection"


RULES = [
    is_bad_path,
    is_masquerading,
    is_bad_parent_child,
    is_bad_cmdline,
    is_suspicious_dlls,
]