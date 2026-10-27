from heuristics import RULES, check_signature, is_suspicious_dlls


# Тут подпись проверяем только после того, как другое правило уже дало баллы.
def score_process(info):
    total_score = 0
    reasons = []

    for rule in RULES:
        if rule is is_suspicious_dlls and not total_score:
            continue
        triggered, weight, rule_name = rule(info)
        if triggered:
            total_score += weight
            reasons.append(rule_name)

    if total_score:
        triggered, weight, rule_name = check_signature(info)
        if triggered:
            total_score += weight
            reasons.append(rule_name)

    return total_score, reasons
