DB_NAME = "antivirus.db"

WARNING_SCALE = 30

WEIGHT_BAD_PATH = 30
WEIGHT_MASQUERADING = 50
WEIGHT_OFFICE_SPAWNS_SHELL = 60
WEIGHT_BAD_CMDLINE = 15
WEIGHTS = {
    "bad_path": WEIGHT_BAD_PATH,
    "masquerading": WEIGHT_MASQUERADING,
    "office_spawns_shell": WEIGHT_OFFICE_SPAWNS_SHELL,
    "bad_cmdline": WEIGHT_BAD_CMDLINE,
}

BAD_DIRS = (
    "\\temp\\",
    "\\appdata\\roaming\\",
)
