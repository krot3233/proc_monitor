import os

from config import BAD_DIRS, WEIGHT_BAD_PATH


def is_bad_path(exe):
    if not exe:
        return False, 0, "bad_path"

    path = os.path.normcase(exe).lower()

    for bad_dir in BAD_DIRS:
        if bad_dir in path:
            return True, WEIGHT_BAD_PATH, "bad_path"

    return False, 0, "bad_path"


RULES = [is_bad_path]

SUSPICIOUS_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".txt", ".rtf",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".js", ".vbs", ".ps1", ".bat", ".cmd", ".scr", ".pif",
}

NORMAL_EXTS = {".exe", ".com", ".dll", ".so", ".bin", ".app", ".run"}


def check_suspicious_extension(proc):
    exe = (proc.get("exe") or proc.get("name") or "").lower().strip()
    if not exe:
        return None

    parts = exe.split(".")

    if len(parts) >= 3:
        last = "." + parts[-1]
        prev = "." + parts[-2]
        if last in NORMAL_EXTS and prev in SUSPICIOUS_EXTS:
            return {
                "rule": "double_extension",
                "weight": 45,
                "description": f'Double extension detected: "{exe}"',
            }

    last = "." + parts[-1] if len(parts) > 1 else ""
    if last in SUSPICIOUS_EXTS:
        return {
            "rule": "suspicious_extension",
            "weight": 35,
            "description": f'Suspicious executable extension: "{exe}"',
        }

    return None
    
