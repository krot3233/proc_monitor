DB_NAME = "antivirus.db"

WARNING_SCALE = 30

WEIGHT_BAD_PATH = 30
WEIGHT_MASQUERADING = 50
WEIGHT_OFFICE_SPAWNS_SHELL = 60
WEIGHT_BAD_CMDLINE = 15
WEIGHT_UNSIGNED = 40
WEIGHT_INJECTION_SUSPICIOUS_DLL = 40
WEIGHTS = {
    "bad_path": WEIGHT_BAD_PATH,
    "masquerading": WEIGHT_MASQUERADING,
    "office_spawns_shell": WEIGHT_OFFICE_SPAWNS_SHELL,
    "bad_cmdline": WEIGHT_BAD_CMDLINE,
    "unsigned": WEIGHT_UNSIGNED,
    "suspicious_dll_injection": WEIGHT_INJECTION_SUSPICIOUS_DLL,
}

BAD_DIRS = (
    "\\temp\\",
    "\\appdata\\roaming\\",
)
