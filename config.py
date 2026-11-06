import os
from pathlib import Path


DB_NAME = str(Path(__file__).resolve().parent / "antivirus.db")
LOG_NAME = str(Path(__file__).resolve().parent / "antivirus.log")

# Отдельные признаки складываются в общий балл; порог события задается ниже.
WARNING_SCALE = 30

WEIGHT_BAD_PATH = 20
WEIGHT_MASQUERADING = 50
WEIGHT_OFFICE_SPAWNS_SHELL = 60
WEIGHT_BAD_CMDLINE = 15
WEIGHT_UNSIGNED = 40
WEIGHT_INJECTION_SUSPICIOUS_DLL = 40
WEIGHT_UNTRUSTED_DLL = 20
WEIGHT_SIGNED_BAD_PATH = 10
WEIGHT_SIGNED_LOLBIN_BAD_PATH = 30
WEIGHTS = {
    "bad_path": WEIGHT_BAD_PATH,
    "masquerading": WEIGHT_MASQUERADING,
    "office_spawns_shell": WEIGHT_OFFICE_SPAWNS_SHELL,
    "bad_cmdline": WEIGHT_BAD_CMDLINE,
    "unsigned": WEIGHT_UNSIGNED,
    "suspicious_dll_injection": WEIGHT_INJECTION_SUSPICIOUS_DLL,
    "unsigned_dll": WEIGHT_UNTRUSTED_DLL,
    "signed_bad_path": WEIGHT_SIGNED_BAD_PATH,
    "signed_lolbin_bad_path": WEIGHT_SIGNED_LOLBIN_BAD_PATH,
}

# Эти каталоги часто используют для запуска временных или скачанных файлов.
BAD_DIRS = []
user_profile = os.environ.get("USERPROFILE")
for directory in (
    os.environ.get("TEMP"),
    os.environ.get("TMP"),
    os.environ.get("APPDATA"),
    os.path.join(
        os.environ.get("WINDIR") or os.environ.get("SystemRoot", r"C:\Windows"),
        "Temp",
    ),
    os.environ.get("ProgramData"),
    os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public")),
    os.path.join(user_profile, "Downloads") if user_profile else None,
):
    if directory:
        normalized = os.path.normcase(os.path.abspath(directory)).lower()
        if normalized not in BAD_DIRS:
            BAD_DIRS.append(normalized)
