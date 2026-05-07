def analyze_risk(network, duplicate_ssids):
    score = 100
    reasons = []

    security = network.get("security", "").lower()
    signal = int(network.get("signal", 0))
    ssid = network.get("ssid", "")

    if security == "open" or security == "":
        score -= 60
        reasons.append("Open network with no password")

    if "wep" in security:
        score -= 50
        reasons.append("Weak WEP encryption detected")

    if security == "wpa":
        score -= 25
        reasons.append("Older WPA security detected")

    if signal < 40:
        score -= 10
        reasons.append("Weak signal strength")

    if ssid in duplicate_ssids:
        score -= 20
        reasons.append("Duplicate network name detected")

    score = max(score, 0)

    if score >= 80:
        risk = "Safe"
        advice = "This network looks reasonably safe."
    elif score >= 50:
        risk = "Moderate"
        advice = "Use caution. Prefer using a VPN."
    else:
        risk = "Dangerous"
        advice = "Avoid connecting to this network."

    return {
        "score": score,
        "risk": risk,
        "advice": advice,
        "reasons": reasons
    }