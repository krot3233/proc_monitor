from db import is_whitelisted
from heuristics import RULES
from heuristics import check_suspicious_extension


def score_process(exe, name):
    if is_whitelisted(name):
        return 0, []

    total_score = 0
    reasons = []

    for rule in RULES:
        result = rule(exe)
        triggered = result[0]
        weight = result[1]
        rule_name = result[2]
        if triggered:
            total_score += weight
            reasons.append(rule_name)

    return total_score, reasons
