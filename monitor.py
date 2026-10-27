from datetime import datetime

import psutil

from config import WARNING_SCALE, WEIGHTS
from db import is_whitelisted, log_event
from models import ProcInfo
from scoring import score_process


def format_time(create_time):
    if create_time > 0:
        return datetime.fromtimestamp(create_time).strftime("%H:%M:%S")
    return "--:--:--"


def build_info(proc):
    try:
        with proc.oneshot():
            parent = proc.parent()
            try:
                exe = proc.exe() or ""
            except psutil.AccessDenied:
                exe = ""
            return ProcInfo(
                pid=proc.pid,
                name=proc.name(),
                exe=exe if exe else "",
                cmdline=proc.cmdline(),
                ppid=proc.ppid(),
                parent_name=parent.name() if parent else "",
                create_time=proc.create_time(),
            )
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return None


def monitor_once(seen, startup=False):
    active = set()
    procs = []

    for proc in psutil.process_iter():
        info = build_info(proc)
        if info is None:
            continue

        active.add((info.pid, info.create_time))
        procs.append(info)

    procs.sort(key=lambda info: info.create_time)

    for info in procs:
        key = (info.pid, info.create_time)
        if key in seen and not startup:
            continue

        started = format_time(info.create_time)
        status = "[STARTUP]" if startup else "[NEW]"
        print(status, started, info.pid, info.name, info.exe)

        if is_whitelisted(info.name, info.exe):
            print("[WHITELISTED]", started, info.pid, info.name)
            continue

        score, reasons = score_process(info)

        if score >= WARNING_SCALE:
            for rule in reasons:
                weight = WEIGHTS.get(rule, 0)
                print("[SUSPECT]", started, info.pid, info.name, score, rule)
                log_event(
                    info.pid,
                    info.name,
                    info.exe,
                    rule,
                    weight,
                    score,
                )

    return active


def monitor_loop(stop_event, sleep_interval=2.0):
    if stop_event.is_set():
        return

    seen = monitor_once(set(), startup=True)

    while not stop_event.is_set():
        seen = monitor_once(seen)
        stop_event.wait(sleep_interval)