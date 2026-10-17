#  AI Email Phishing Analyzer

An AI-powered cybersecurity application that analyzes email content to detect potential phishing threats using machine learning, rule-based detection, and Large Language Models (LLMs). The application calculates a risk score, identifies suspicious indicators, and generates AI-powered threat reports through an interactive Streamlit dashboard.

##  Features

- **Machine Learning Detection:** Uses a trained classification model to estimate the phishing risk of an email.
- **Rule-Based Analysis:** Detects suspicious language, excessive capitalization, multiple URLs, shortened links, and IP-based URLs.
- **Attachment Analysis:** Flags potentially dangerous attachment extensions such as `.exe`, `.bat`, `.js`, `.vbs`, `.ps1`, `.scr`, `.docm`, and `.xlsm`.
- **Email Header Analysis:** Identifies mismatches between sender and Reply-To email addresses.
- **Risk Scoring Engine:** Combines machine learning predictions and rule-based scores to calculate an overall risk score.
- **AI-Generated Threat Reports:** Uses the OpenRouter API to generate threat summaries, explain suspicious indicators, categorize attacks, and suggest mitigation steps.
- **Interactive Dashboard:** Visualizes risk distribution and risk score patterns using Plotly.
- **Session-Based Analysis History:** Tracks analyzed emails within the current Streamlit session.

##  Tech Stack

| Technology | Purpose |
|---|---|
| Python | Core application and analysis logic |
| Streamlit | Interactive web interface |
| Scikit-learn | Machine learning classification |
| Joblib | Loading serialized ML artifacts |
| NumPy | Numerical operations |
| Pandas | Data handling and dashboard data |
| Plotly | Interactive data visualizations |
| OpenAI Python SDK | LLM API integration |
| OpenRouter API | AI-powered threat report generation |

##  Project Structure

```text
Email Phishing Analyzer/
├── app.py                       # Streamlit application
├── analysis_engine.py            # Phishing detection and risk scoring
├── AIEmailPhishingAnalyzer.ipynb # Model experimentation notebook
├── test_backend.py               # Backend test script
├── models/
│   ├── model.pkl                 # Trained classification model
│   └── vectorizer.pkl            # Text vectorizer
├── .env                          # Local environment variables
└── README.md                     # Project documentation
```



##  Detection Methodology

The application combines machine learning predictions with rule-based analysis.

### 1. Machine Learning Analysis

The email text is preprocessed and transformed using a saved vectorizer. A trained classification model estimates the phishing probability.

### 2. Rule-Based Detection

The rule engine examines email content for indicators such as:

- Urgent or manipulative phrases.
- Multiple URLs.
- IP-address-based URLs.
- Shortened URLs.
- Excessive capitalization.

### 3. Attachment and Header Analysis

The application flags selected risky filename extensions and checks whether the sender and Reply-To addresses differ.

### 4. Combined Risk Score

The final score is calculated using a weighted combination of the machine learning score and the aggregated rule-based score:

**Final Risk Score = (0.7 × ML Score) + (0.3 × Rule Score)**

The rule score incorporates content indicators, attachment findings, and header mismatches, capped at 100 before the final calculation.

### 5. Risk Classification

| Risk Score | Classification |
|---:|---|
| 0–24.99 | Low |
| 25–49.99 |Medium |
| 50–74.99 | High |
| 75–100 |  Critical |

### 6. AI Threat Report

The OpenRouter API provides an LLM-generated report containing:

- Threat summary.
- Risk explanation.
- Potential attack category.
- Recommended mitigation steps.
- Security awareness tips.

##  Dashboard

The Streamlit dashboard provides visual insights into the emails analyzed during the current session.

- Risk Distribution: Displays the distribution of Low, Medium, High, and Critical classifications.
- Risk Score Histogram: Shows the distribution of calculated risk scores.
- Total Emails: Displays the number of emails analyzed in the current session.

## Testing

Run the provided backend test script from the project root:

```bash
python test_backend.py
```

The test exercises the analysis pipeline using a sample suspicious email. Ensure that the required model files and Python dependencies are available.



##  Security and Privacy

- Avoid submitting confidential emails or sensitive personal data to external AI services unless authorized.
- Never expose API keys or credentials in source code or public repositories.
- Treat all detection results as risk indicators rather than definitive proof.
- Verify suspicious emails through trusted channels before interacting with links or attachments.

