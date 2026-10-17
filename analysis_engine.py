
import re
import joblib
import numpy as np

# ======================
# Load Model
# ======================

model = joblib.load("models/model.pkl")
vectorizer = joblib.load("models/vectorizer.pkl")

# ======================
# Text Preprocessing
# ======================

def preprocess(text):
    text = text.lower()
    text = re.sub(r"http\\S+", "", text)
    text = re.sub(r"[^a-zA-Z\\s]", " ", text)
    return text

# ======================
# Email Parser
# ======================

#URL_REGEX = r'https?://[^\\s]+'
URL_REGEX = r'https?://[^\s]+'

def extract_urls(text):
    return re.findall(URL_REGEX, text)

def parse_email_text(email_text):

    return {
        "body": email_text,
        "urls": extract_urls(email_text)
    }

# ======================
# Feature Extraction
# ======================

URGENT_WORDS = [
    "urgent",
    "verify",
    "account suspended",
    "click now",
    "immediate action",
    "password reset",
    "security alert"
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co"
]

def detect_urgent_words(text):

    text = text.lower()

    return [
        word
        for word in URGENT_WORDS
        if word in text
    ]

# def capital_ratio(text):

#     letters = [
#         c
#         for c in text
#         if c.isalpha()
#     ]

#     if len(letters) == 0:
#         return 0

#     capitals = [
#         c
#         for c in letters
#         if c.isupper()
#     ]

#     return len(capitals) / len(letters)
def capital_ratio(text):
    letters = [c for c in text if c.isalpha()]
    
    if len(letters) == 0:
        return 0

    capitals = [c for c in text if c.isupper()]

    return len(capitals) / len(letters)

def is_ip_url(url):

    return bool(
        re.search(
            r'https?://\\d+\\.\\d+\\.\\d+\\.\\d+',
            url
        )
    )

def is_shortened_url(url):

    return any(
        s in url
        for s in SHORTENERS
    )

def extract_features(parsed_email):

    urls = parsed_email["urls"]
    body = parsed_email["body"]

    return {
        "url_count": len(urls),
        "urgent_words": detect_urgent_words(body),
        "urgent_count": len(
            detect_urgent_words(body)
        ),
        "capital_ratio": capital_ratio(body),
        "ip_urls": sum(
            is_ip_url(url)
            for url in urls
        ),
        "short_urls": sum(
            is_shortened_url(url)
            for url in urls
        )
    }

# ======================
# Rule Engine
# ======================

def calculate_rule_score(features):

    score = 0
    indicators = []

    if features["urgent_count"] > 0:
        score += 10
        indicators.append(
            f"Urgent language detected ({features['urgent_words']})"
        )

    if features["url_count"] > 3:
        score += 10
        indicators.append(
            "Multiple URLs detected"
        )

    if features["ip_urls"] > 0:
        score += 15
        indicators.append(
            "IP-based URL detected"
        )

    if features["short_urls"] > 0:
        score += 10
        indicators.append(
            "Shortened URL detected"
        )

    if features["capital_ratio"] > 0.30:
        score += 5
        indicators.append(
            "Excessive capitalization"
        )

    return {
        "rule_score": min(score, 100),
        "indicators": indicators
    }

# ======================
# Attachment Analysis
# ======================

DANGEROUS_EXTENSIONS = [
    ".exe",
    ".bat",
    ".js",
    ".vbs",
    ".scr",
    ".ps1",
    ".docm",
    ".xlsm"
]

def analyze_attachments(files):

    findings = []
    score = 0

    for file in files:

        file = file.lower()

        for ext in DANGEROUS_EXTENSIONS:

            if file.endswith(ext):

                findings.append(
                    f"Dangerous attachment: {file}"
                )

                score += 20

    return {
        "attachment_score": score,
        "findings": findings
    }

# ======================
# Header Analysis
# ======================

def analyze_headers(
    from_email,
    reply_to
):

    findings = []
    score = 0

    if (
        from_email
        and reply_to
        and from_email.lower()
        != reply_to.lower()
    ):

        findings.append(
            "Reply-To mismatch detected"
        )

        score += 15

    return {
        "header_score": score,
        "findings": findings
    }

# ======================
# ML Scoring
# ======================

def get_ml_score(email_text):

    clean_text = preprocess(email_text)

    vector = vectorizer.transform(
        [clean_text]
    )

    probability = model.predict_proba(
        vector
    )[0][1]

    return float(probability * 100)

# ======================
# Risk Fusion
# ======================

def calculate_final_risk(
    ml_score,
    rule_score
):

    return round(
        (0.7 * ml_score)
        +
        (0.3 * rule_score),
        2
    )

def classify_risk(score):

    if score < 25:
        return "Low"

    elif score < 50:
        return "Medium"

    elif score < 75:
        return "High"

    return "Critical"

# ======================
# OpenRouter Integration
# ======================

import os
from openai import OpenAI

def get_openrouter_client():

    #api_key = os.getenv("OPENROUTER_API_KEY")
   
    return OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key
    )

# ======================
# Prompt Builder
# ======================

def build_prompt(
    email_text,
    analysis_result
):

    return f"""
You are a cybersecurity phishing analyst.

EMAIL:
{email_text}

RISK SCORE:
{analysis_result['final_score']}

RISK LEVEL:
{analysis_result['risk_level']}

INDICATORS:
{analysis_result['indicators']}

Provide:

1. Threat Summary

2. Risk Explanation

3. Attack Category
(Credential Theft, Malware, BEC, Scam, Other)

4. Recommendations

5. Security Awareness Tips

Keep the response concise and professional.
"""

# ======================
# Threat Report
# ======================

def generate_threat_report(
    email_text,
    analysis_result,
    model_name="openai/gpt-4o-mini"
):

    client = get_openrouter_client()

    prompt = build_prompt(
        email_text,
        analysis_result
    )

    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.2
    )

    return response.choices[0].message.content

# ======================
# Complete Analysis
# ======================

def analyze_email_complete(
    email_text,
    attachments=None,
    from_email=None,
    reply_to=None
):

    if attachments is None:
        attachments = []

    parsed = parse_email_text(
        email_text
    )

    features = extract_features(
        parsed
    )

    rule_result = calculate_rule_score(
        features
    )

    ml_score = get_ml_score(
        email_text
    )

    attachment_result = analyze_attachments(
        attachments
    )

    header_result = analyze_headers(
        from_email,
        reply_to
    )

    total_rule_score = (
        rule_result["rule_score"]
        +
        attachment_result["attachment_score"]
        +
        header_result["header_score"]
    )

    total_rule_score = min(
        total_rule_score,
        100
    )

    final_score = calculate_final_risk(
        ml_score,
        total_rule_score
    )

    risk_level = classify_risk(
        final_score
    )

    indicators = (
        rule_result["indicators"]
        +
        attachment_result["findings"]
        +
        header_result["findings"]
    )

    return {
        "ml_score": round(
            float(ml_score), 2
        ),
        "rule_score": total_rule_score,
        "final_score": round(
            float(final_score), 2
        ),
        "risk_level": risk_level,
        "indicators": indicators
    }
