from flask import Flask, render_template, request
import pickle
import re

app = Flask(__name__)

# -------------------------
# LOAD MODEL + VECTORIZER
# -------------------------
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

with open("vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

# -------------------------
# SUSPICIOUS PATTERNS
# -------------------------
PATTERN_RULES = [
    ("UNION keyword", r"\bunion\b"),
    ("SELECT keyword", r"\bselect\b"),
    ("DROP keyword", r"\bdrop\b"),
    ("INSERT keyword", r"\binsert\b"),
    ("DELETE keyword", r"\bdelete\b"),
    ("UPDATE keyword", r"\bupdate\b"),
    ("OR 1=1 tautology", r"\bor\s+1\s*=\s*1\b"),
    ("SQL comment '--'", r"--"),
    ("Single quote", r"'"),
    ("Double quote", r'"'),
    ("Semicolon", r";"),
    ("<script> tag", r"<script.*?>"),
    ("Encoded quote/token", r"%27|%3c|%3e|%22"),
    ("information_schema reference", r"\binformation_schema\b"),
    ("xp_cmdshell reference", r"\bxp_cmdshell\b"),
    ("sleep/time-based pattern", r"\bsleep\s*\("),
    ("benchmark/time-based pattern", r"\bbenchmark\s*\("),
]

SQL_WORDS = [
    "select", "union", "drop", "insert", "delete", "update",
    "from", "where", "table", "database", "information_schema",
    "or", "and", "sleep", "benchmark"
]

def get_matched_patterns(payload: str):
    payload_lower = payload.lower()
    matches = []

    for label, pattern in PATTERN_RULES:
        found = re.findall(pattern, payload_lower)
        if found:
            sample = found[0] if isinstance(found[0], str) else str(found[0])
            matches.append((label, sample))

    return matches

def get_payload_stats(payload: str):
    length = len(payload)
    special_chars = re.findall(r"[<>'\";=%\-\(\)]", payload)
    digits = sum(ch.isdigit() for ch in payload)
    alpha = sum(ch.isalpha() for ch in payload)
    spaces = sum(ch.isspace() for ch in payload)
    words = re.findall(r"\b[a-zA-Z_]+\b", payload.lower())
    sql_terms = [w for w in words if w in SQL_WORDS]

    return {
        "length": length,
        "special_count": len(special_chars),
        "special_unique": sorted(set(special_chars)),
        "digit_count": digits,
        "alpha_count": alpha,
        "space_count": spaces,
        "sql_terms": sorted(set(sql_terms)),
        "is_plain_text": bool(re.fullmatch(r"[a-zA-Z0-9\s]+", payload.strip())) and len(payload.strip()) > 0,
        "has_email_like": bool(re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", payload)),
        "has_assignment_like": bool(re.search(r"\b\w+\s*=\s*\w+", payload)),
    }

def obvious_safe_input(payload: str, matches, stats):
    text = payload.strip()

    if not text:
        return False

    if matches:
        return False

    if stats["is_plain_text"] and len(text.split()) <= 8:
        return True

    if stats["has_email_like"]:
        return True

    if stats["has_assignment_like"] and stats["special_count"] <= 1 and len(stats["sql_terms"]) == 0:
        return True

    return False

def build_explanation(payload: str, label: int, confidence: float, matches, stats, safe_prob, malicious_prob):
    parts = []

    if label == 1:
        parts.append("The payload is classified as malicious")

        if matches:
            readable = [f"{name} ({sample})" for name, sample in matches[:5]]
            parts.append("because it contains suspicious attack indicators such as " + ", ".join(readable))

        if stats["sql_terms"]:
            parts.append("it includes SQL-related terms like " + ", ".join(stats["sql_terms"][:5]))

        if stats["special_count"] >= 3:
            parts.append(f"it contains {stats['special_count']} suspicious special characters")

        if not matches and not stats["sql_terms"]:
            parts.append("the model found character patterns similar to attack payloads in the training data")

        parts.append(f"malicious probability is {malicious_prob:.2f}%")
        return ". ".join(parts) + "."

    else:
        parts.append("The payload is classified as safe")

        safe_reasons = []

        if stats["is_plain_text"]:
            safe_reasons.append("it looks like normal plain text")

        if stats["has_email_like"]:
            safe_reasons.append("it looks like a normal email-style input")

        if stats["has_assignment_like"] and len(stats["sql_terms"]) == 0:
            safe_reasons.append("it looks like a simple key-value input")

        if not matches:
            safe_reasons.append("no known SQL/XSS attack patterns were detected")

        if stats["special_count"] <= 1:
            safe_reasons.append("it contains very few suspicious special characters")

        if not safe_reasons:
            safe_reasons.append("the model did not find strong evidence of malicious behavior")

        parts.append("because " + ", ".join(safe_reasons[:4]))
        parts.append(f"safe probability is {safe_prob:.2f}%")
        return ". ".join(parts) + "."

def hybrid_predict(payload: str):
    payload = payload.strip()
    matches = get_matched_patterns(payload)
    stats = get_payload_stats(payload)

    # very obvious safe input shortcut
    if obvious_safe_input(payload, matches, stats):
        safe_prob = 97.0
        malicious_prob = 3.0
        explanation = build_explanation(
            payload, 0, safe_prob, matches, stats, safe_prob, malicious_prob
        )
        return 0, safe_prob, explanation

    vec = vectorizer.transform([payload])
    probs = model.predict_proba(vec)[0]
    safe_prob = float(probs[0] * 100)
    malicious_prob = float(probs[1] * 100)

    strong_malicious_patterns = [
        r"\bor\s+1\s*=\s*1\b",
        r"\bunion\b.*\bselect\b",
        r"<script.*?>",
        r"--",
        r"\bdrop\b",
        r"\binformation_schema\b",
        r"\bxp_cmdshell\b"
    ]

    if any(re.search(p, payload.lower()) for p in strong_malicious_patterns):
        confidence = max(malicious_prob, 95.0)
        explanation = build_explanation(
            payload, 1, confidence, matches, stats, safe_prob, confidence
        )
        return 1, confidence, explanation

    if malicious_prob >= 65:
        explanation = build_explanation(
            payload, 1, malicious_prob, matches, stats, safe_prob, malicious_prob
        )
        return 1, malicious_prob, explanation
    else:
        explanation = build_explanation(
            payload, 0, safe_prob, matches, stats, safe_prob, malicious_prob
        )
        return 0, safe_prob, explanation

# -------------------------
# ROUTES
# -------------------------
@app.route("/")
def home():
    return render_template(
        "index.html",
        prediction=None,
        prediction_class="",
        explanation=None,
        confidence=None,
        user_input=""
    )

@app.route("/predict", methods=["POST"])
def predict():
    payload = request.form.get("payload", "").strip()

    if not payload:
        return render_template(
            "index.html",
            prediction="Please enter a payload",
            prediction_class="warning",
            explanation="No input was provided, so the system could not analyze anything.",
            confidence=0,
            user_input=""
        )

    label, confidence, explanation = hybrid_predict(payload)

    if label == 1:
        prediction = "⚠ Malicious Payload"
        prediction_class = "malicious"
    else:
        prediction = "✅ Safe Payload"
        prediction_class = "safe"

    return render_template(
        "index.html",
        prediction=prediction,
        prediction_class=prediction_class,
        explanation=explanation,
        confidence=round(confidence, 2),
        user_input=payload
    )

if __name__ == "__main__":
    app.run(debug=True)