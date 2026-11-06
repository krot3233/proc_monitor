import base64
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from config import WARNING_SCALE

LIFETIME = 30
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


# Запускаем PowerShell с подозрительной строкой, но без сетевых действий.
def signature_check(_folder):
    return subprocess.Popen(
        [
            str(POWERSHELL),
            "-NoProfile",
            "-Command",
            f"Write-Output 'downloadstring'; Start-Sleep -Seconds {LIFETIME}",
        ]
    )


# Копия подписана, но лежит во временной папке под именем системной утилиты.
def signed_lolbin(folder):
    exe = copy_exe(CMD, folder, "cmd.exe")
    return subprocess.Popen(
        [str(exe), "/c", f"ping -n {LIFETIME} 127.0.0.1"]
    )


# Имя и аргументы имитируют mshta с URL; команда только запускает локальный ping.
def lolbin_url(folder):
    exe = copy_exe(CMD, folder, "mshta.exe")
    return subprocess.Popen(
        [
            str(exe),
            "/c",
            f"ping -n {LIFETIME} 127.0.0.1 & rem http://example.invalid/x.hta",
        ]
    )


# В каждой записи: название, функция запуска, ожидаемый результат и папка для копии.
SCENARIOS = [
    ("Обычный ping", clean, "0 баллов", False),
    ("Подписанный ping из Temp", bad_path, "signed_bad_path: 10 (ниже порога событий 30)", True),
    ("svchost.exe не в System32", masquerading, "masquerading: 50", False),
    ("Office запускает cmd", office_shell, "office_spawns_shell: 60", False),
    ("PowerShell с Bypass и Hidden", bad_cmdline, "bad_cmdline: 45", False),
    ("Только EncodedCommand", encoded_command, "bad_cmdline: 15 (ниже порога событий 30)", False),
    ("svchost.exe в Temp", combined, "masquerading: 50 + signed_bad_path: 10 = 60", True),
    (
        "Проверка подписи PowerShell",
        signature_check,
        "bad_cmdline: 15 (ниже порога событий 30); подпись исполняемого файла проверяется",
        False,
    ),
    ("Копия cmd.exe в Temp", signed_lolbin, "signed_lolbin_bad_path: 30", True),
    ("mshta.exe с URL в аргументах", lolbin_url, "bad_cmdline: 30", False),
]


def show_scenarios():
    for number, item in enumerate(SCENARIOS, start=1):
        print(f"{number}. {item[0]}: {item[2]}")


def run_scenario(number):
    title, start, expected, use_temp = SCENARIOS[number]
    root = tempfile.gettempdir() if use_temp else str(Path.home())

    print(f"\nСценарий: {title}")
    print(f"Ожидается: {expected}; порог предупреждения: {WARNING_SCALE}")

    # Временная папка удалится после завершения процесса, в том числе при таймауте.
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