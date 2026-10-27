import base64
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from config import WARNING_SCALE

LIFETIME = 8
WINDOWS = Path(os.environ.get("SystemRoot", r"C:\Windows"))
SYSTEM32 = WINDOWS / "System32"
PING = SYSTEM32 / "ping.exe"
CMD = SYSTEM32 / "cmd.exe"
POWERSHELL = SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def copy_exe(source, folder, name):
    target = folder / name
    shutil.copy2(source, target)
    return target


def clean(_folder):
    return subprocess.Popen(
        [str(PING), "-n", str(LIFETIME), "127.0.0.1"]
    )


def bad_path(folder):
    exe = copy_exe(PING, folder, "sample.exe")
    return subprocess.Popen([str(exe), "-n", str(LIFETIME), "127.0.0.1"])


def masquerading(folder):
    exe = copy_exe(PING, folder, "svchost.exe")
    return subprocess.Popen([str(exe), "-n", str(LIFETIME), "127.0.0.1"])


def office_shell(folder):
    word = copy_exe(CMD, folder, "winword.exe")
    return subprocess.Popen(
        [str(word), "/c", "cmd.exe", "/c", "ping", "-n", str(LIFETIME), "127.0.0.1"]
    )


def bad_cmdline(_folder):
    return subprocess.Popen(
        [
            str(POWERSHELL),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "-Command",
            f"Start-Sleep -Seconds {LIFETIME}",
        ]
    )


def encoded_command(_folder):
    cmd = f"Start-Sleep -Seconds {LIFETIME}"
    data = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
    return subprocess.Popen([str(POWERSHELL), "-EncodedCommand", data])


def combined(folder):
    exe = copy_exe(PING, folder, "svchost.exe")
    return subprocess.Popen([str(exe), "-n", str(LIFETIME), "127.0.0.1"])


# Тут запускаем Python с подозрительным аргументом, чтобы проверить подпись.
def signature_check(_folder):
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            f"import time; time.sleep({LIFETIME})",
            "downloadstring",
        ]
    )


# Для теста загрузи безопасную DLL через ctypes в свой процесс и оставь его работать.
# Запусти процесс из Temp или с подозрительным аргументом, иначе проверка DLL не включится.
SCENARIOS = [
    ("Обычный ping", clean, "0 баллов", False),
    ("Запуск из Temp", bad_path, "bad_path: 30", True),
    ("svchost.exe не в System32", masquerading, "masquerading: 50", False),
    ("Office запускает cmd", office_shell, "office_spawns_shell: 60", False),
    ("PowerShell с Bypass и Hidden", bad_cmdline, "bad_cmdline: 45", False),
    ("Только EncodedCommand", encoded_command, "bad_cmdline: 15", False),
    ("svchost.exe в Temp", combined, "bad_path + masquerading: 80", True),
    (
        "Проверка подписи Python",
        signature_check,
        "bad_cmdline: 15; +40, если Python без действительной подписи",
        False,
    ),
]


def show_scenarios():
    for number, item in enumerate(SCENARIOS, start=1):
        print(f"{number}. {item[0]}: {item[2]}")


def run_scenario(number):
    title, start, expected, use_temp = SCENARIOS[number]
    root = tempfile.gettempdir() if use_temp else str(Path.home())

    print(f"\nСценарий: {title}")
    print(f"Ожидается: {expected}; порог предупреждения: {WARNING_SCALE}")

    with tempfile.TemporaryDirectory(prefix="av_demo_", dir=root) as folder:
        proc = start(Path(folder))
        try:
            proc.wait(timeout=LIFETIME + 5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def main():

    args = sys.argv[1:]
    if args == ["--list"]:
        show_scenarios()
        return
    if args == ["--all"]:
        numbers = range(len(SCENARIOS))
    elif args:
        try:
            numbers = [int(arg) - 1 for arg in args]
        except ValueError:
            print("Укажи номер сценария, --all или --list.")
            return
    else:
        show_scenarios()
        choice = input("Введи номер сценария или all: ").strip().lower()
        if choice == "all":
            numbers = range(len(SCENARIOS))
        else:
            try:
                numbers = [int(choice) - 1]
            except ValueError:
                print("Нужно ввести номер или all.")
                return
            
    for number in numbers:
        run_scenario(number)



if __name__ == "__main__":
    main()