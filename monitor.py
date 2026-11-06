import logging
import sqlite3
import time
from datetime import datetime

import psutil

from config import WARNING_SCALE, WEIGHTS
from db import log_event
from models import ProcInfo
from scoring import score_process

logger = logging.getLogger(__name__)


def format_time(create_time):
    if create_time > 0:
        return datetime.fromtimestamp(create_time).strftime("%H:%M:%S")
    return "--:--:--"


def build_info(proc):
    try:
        with proc.oneshot():
            # У защищенных процессов часть полей недоступна без прав администратора.
            try:
                name = proc.name() or f"process-{proc.pid}"
            except psutil.AccessDenied:
                name = f"process-{proc.pid}"

            try:
                exe = proc.exe() or ""
            except psutil.AccessDenied:
                exe = ""

            try:
                cmdline = proc.cmdline()
            except psutil.AccessDenied:
                cmdline = []

            try:
                ppid = proc.ppid()
            except psutil.AccessDenied:
                ppid = 0

            try:
                parent = proc.parent()
                parent_name = parent.name() if parent else ""
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                parent_name = ""

            try:
                create_time = proc.create_time()
            except psutil.AccessDenied:
                create_time = 0.0

            return ProcInfo(
                pid=proc.pid,
                name=name,
                exe=exe if exe else "",
                cmdline=cmdline,
                ppid=ppid,
                parent_name=parent_name,
                create_time=create_time,
            )
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return None


def monitor_once(
    seen,
    startup=False,
    last_checked=None,
    reported=None,
    rescan_interval=15.0,
    stop_event=None,
):
    if last_checked is None:
        last_checked = {}
    if reported is None:
        reported = {}

    active = set()
    procs = []
    now = time.monotonic()

    for proc in psutil.process_iter():
        # Останавливаем обход, не дожидаясь завершения всего списка процессов.
        if stop_event is not None and stop_event.is_set():
            return seen
        try:
            create_time = proc.create_time()
        except psutil.AccessDenied:
            create_time = 0.0
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue

        key = (proc.pid, create_time)
        active.add(key)
        if key in seen and not startup:
            # Уже известные процессы подробно перечитываем только по таймеру.
            if now - last_checked.get(key, 0) < rescan_interval:
                continue

        last_checked[key] = now
        info = build_info(proc)
        if info is None:
            continue

        info.create_time = create_time
        procs.append((info, key, key in seen))

    # Сначала обрабатываем более старые процессы, порядок от запуска к запуску стабилен.
    procs.sort(key=lambda item: item[0].create_time)

    for info, key, was_seen in procs:
        if stop_event is not None and stop_event.is_set():
            return seen
        started = format_time(info.create_time)
        status = "[STARTUP]" if startup else "[NEW]"
        if was_seen and not startup:
            status = "[CHECK]"
        logger.debug("%s %s %s %s %s", status, started, info.pid, info.name, info.exe)

        try:
            score, reasons = score_process(info)
        except Exception:
            logger.exception(
                "Не удалось оценить процесс %s (%s)",
                info.name,
                info.pid,
            )
            continue

        if score >= WARNING_SCALE:
            # Одно и то же правило для живого процесса записываем только один раз.
            process_reported = reported.setdefault(key, set())
            for rule in reasons:
                if rule in process_reported:
                    continue
                weight = WEIGHTS.get(rule, 0)
                try:
                    log_event(
                        info.pid,
                        info.name,
                        info.exe,
                        rule,
                        weight,
                        score,
                    )
                except sqlite3.Error:
                    logger.exception(
                        "Не удалось записать событие для процесса %s",
                        info.pid,
                    )
                else:
                    logger.warning(
                        "[SUSPECT] %s %s %s score=%s rule=%s",
                        started,
                        info.pid,
                        info.name,
                        score,
                        rule,
                    )
                    process_reported.add(rule)

    active_keys = set(active)
    for key in list(last_checked):
        if key not in active_keys:
            del last_checked[key]
    for key in list(reported):
        if key not in active_keys:
            del reported[key]

    return active


def monitor_loop(stop_event, sleep_interval=2.0):
    if stop_event.is_set():
        return

    last_checked = {}
    reported = {}
    try:
        seen = monitor_once(
            set(),
            startup=True,
            last_checked=last_checked,
            reported=reported,
            stop_event=stop_event,
        )
    except Exception:
        logger.exception("Ошибка начального сканирования процессов.")
        seen = set()

    while not stop_event.is_set():
        try:
            seen = monitor_once(
                seen,
                last_checked=last_checked,
                reported=reported,
                stop_event=stop_event,
            )
        except Exception:
            logger.exception("Ошибка цикла сканирования процессов.")
        stop_event.wait(sleep_interval)