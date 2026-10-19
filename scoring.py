from heuristics import RULES


def score_process(info):
    total_score = 0
    reasons = []

    for rule in RULES:
        triggered, weight, rule_name = rule(info)
        if triggered:
            total_score += weight
            reasons.append(rule_name)

    return total_score, reasons
