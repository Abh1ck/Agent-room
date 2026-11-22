# 🛡️ PR Guardian AI
### AI-Powered Code Review & Security Analysis

PR Guardian AI is an intelligent code review prototype that combines **Python-based static analysis tools** with **Google Gemini AI** to identify potential security issues, assess code risks, and generate actionable recommendations.

It helps developers understand possible vulnerabilities in their Python code through an interactive dashboard and structured review reports.

## 🚀 Features

- **Python Syntax Checker:** Identifies syntax errors using Python AST parsing.
- **Security Scanner:** Detects potentially unsafe patterns such as `eval()`, `exec()`, hardcoded credentials, and unsafe subprocess configurations.
- **Import Inspector:** Identifies imported Python modules.
- **Gemini AI Review:** Generates explanations and recommendations based on collected analysis findings.
- **Risk Assessment:** Calculates a heuristic risk score based on issue severity.
- **Interactive Dashboard:** Displays findings, risk scores, and visual charts.
- **Fallback Reporting:** Generates a local report when the Gemini API is unavailable.
- **Report Export:** Allows users to download the generated review report.

## 🧠 How It Works

1. Developer submits Python code through the dashboard.
2. The Syntax Checker validates the code.
3. The Security Scanner checks for potentially unsafe patterns.
4. The Import Inspector identifies imported modules.
5. Findings are collected and passed to Gemini for AI-assisted review.
6. The application generates a structured report with severity levels and recommendations.
7. If Gemini is unavailable, the local fallback generates a report using the available analysis results.

## 🏗️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application and analysis tools |
| Streamlit | Interactive web dashboard |
| Google Gemini API | AI-assisted code review |
| Python AST | Syntax and import analysis |
| Regular Expressions | Security pattern detection |
| Pandas | Data handling |
| Plotly | Interactive charts |
| python-dotenv | Environment variable management |

## 📂 Project Structure

```text
Agent-room/
│
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/Abh1ck/Agent-room.git
cd Agent-room
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Gemini API

Create a `.env` file in the project directory:

```env
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-3.8-flash
```

Get your API key from [Google AI Studio](https://aistudio.google.com/apikey).

**Important:** Never upload your actual `.env` file or API key to GitHub.

### 5. Run the application

```bash
streamlit run app.py
```

The application will open in your browser.

## 🔍 Example Security Checks

The scanner looks for patterns such as:

```python
eval(user_input)
```

```python
password = "admin123"
```

```python
subprocess.run(command, shell=True)
```

These patterns are flagged for review. Detection does not automatically prove that code is exploitable.

## 🛡️ Reliability & Security

- Submitted code is analyzed statically and is not executed by the application.
- Gemini is instructed to treat submitted code as untrusted input.
- A local fallback report is available when the Gemini service fails.
- Risk scores are heuristic indicators, not standardized security ratings.
- The prototype may produce false positives or miss vulnerabilities.

## 🔮 Future Improvements

- GitHub Pull Request integration.
- Support for multiple programming languages.
- More advanced vulnerability detection.
- Automated review comments on pull requests.
- Improved severity classification and reporting.
- Deeper code analysis and testing.

## 🎯 Project Objective

To make code reviews more accessible and help developers identify potential security issues earlier by combining traditional static analysis with generative AI.

## 👨‍💻 Developer

**Abhishek Kumar**

GitHub: [@Abh1ck](https://github.com/Abh1ck)

## 📜 Disclaimer

PR Guardian AI is a hackathon prototype and an educational code review assistant. It does not replace professional security audits, comprehensive testing, or established application security tools.
