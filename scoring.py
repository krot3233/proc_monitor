import threading
import time

from db import is_whitelisted
from heuristics import RULES, check_signature, is_suspicious_dlls

SCORE_CACHE_TIME = 30.0
score_cache = {}
score_cache_lock = threading.Lock()
score_pending = {}
score_cache_pruned_at = 0
score_cache_generation = 0


# Монитор и окно могут оценивать один процесс одновременно, поэтому результат общий.
def score_process(info):
    global score_cache_pruned_at

    if is_whitelisted(info.name, info.exe):
        return 0, []

    cache_key = (
        info.pid,
        info.create_time,
        info.name,
        info.exe,
        tuple(info.cmdline),
        info.parent_name,
    )
    while True:
        now = time.monotonic()
        with score_cache_lock:
            cached = score_cache.get(cache_key)
            if cached and now - cached[0] < SCORE_CACHE_TIME:
                return cached[1], list(cached[2])

            if now - score_cache_pruned_at >= SCORE_CACHE_TIME:
                expired = []
                for key, value in score_cache.items():
                    if now - value[0] >= SCORE_CACHE_TIME:
                        expired.append(key)
                for key in expired:
                    del score_cache[key]
                score_cache_pruned_at = now

            # Если другой поток уже считает этот процесс, дождемся его результата.
            pending = score_pending.get(cache_key)
            if pending is None:
                pending = threading.Event()
                score_pending[cache_key] = pending
                generation = score_cache_generation
                break

        pending.wait()

    try:
        total_score = 0
        reasons = []

        for rule in RULES:
            if rule is is_suspicious_dlls:
                triggered, weight, rule_name = rule(
                    info,
                    check_signatures=True,
                )
            else:
                triggered, weight, rule_name = rule(info)
            if triggered:
                total_score += weight
                reasons.append(rule_name)

        if total_score:
            triggered, weight, rule_name = check_signature(info)
            if triggered:
                total_score += weight
                reasons.append(rule_name)
    except Exception:
        with score_cache_lock:
            score_pending.pop(cache_key, None)
            pending.set()
        raise

    stale_result = False
    with score_cache_lock:
        # После сброса кэша старый расчет не должен вернуть устаревший результат.
        if generation == score_cache_generation:
            score_cache[cache_key] = (time.monotonic(), total_score, reasons)
        else:
            stale_result = True
        score_pending.pop(cache_key, None)
    pending.set()

    if stale_result:
        return score_process(info)
    return total_score, reasons


def clear_score_cache():
    global score_cache_generation

    with score_cache_lock:
        score_cache.clear()
        # Версия меняется, чтобы уже запущенные расчеты не заполнили кэш заново.
        score_cache_generation += 1
