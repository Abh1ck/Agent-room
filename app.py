
import os
import re
import ast
import json
import streamlit as st

from dotenv import load_dotenv
from google import genai
from google.genai import types


# =====================================================
# 1. CONFIGURATION
# =====================================================

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

st.set_page_config(
    page_title="PR Guardian AI",
    page_icon="🛡️",
    layout="wide"
)


# =====================================================
# 2. GEMINI CLIENT
# =====================================================

@st.cache_resource
def get_gemini_client():
    if not API_KEY:
        return None

    return genai.Client(api_key=API_KEY)


# =====================================================
# 3. PYTHON ANALYSIS TOOL 1: SYNTAX CHECK
# =====================================================

def check_python_syntax(code):

    try:
        ast.parse(code)

        return {
            "tool": "check_python_syntax",
            "status": "passed",
            "message": "No Python syntax errors detected."
        }

    except SyntaxError as error:

        return {
            "tool": "check_python_syntax",
            "status": "failed",
            "message": f"Line {error.lineno}: {error.msg}"
        }


# =====================================================
# 4. PYTHON ANALYSIS TOOL 2: SECURITY SCANNER
# =====================================================

def scan_security_patterns(code):

    patterns = [
        {
            "pattern": r"\beval\s*\(",
            "severity": "High",
            "title": "Use of eval()",
            "recommendation": (
                "Avoid eval() because it can execute dynamically "
                "supplied code."
            )
        },
        {
            "pattern": r"\bexec\s*\(",
            "severity": "High",
            "title": "Use of exec()",
            "recommendation": (
                "Avoid exec() when processing untrusted input."
            )
        },
        {
            "pattern": r"pickle\.loads?\s*\(",
            "severity": "High",
            "title": "Unsafe pickle deserialization",
            "recommendation": (
                "Never load pickle data from untrusted sources."
            )
        },
        {
            "pattern": r"subprocess\..*shell\s*=\s*True",
            "severity": "High",
            "title": "Subprocess with shell=True",
            "recommendation": (
                "Avoid shell=True with untrusted input. "
                "Prefer passing arguments as a list."
            )
        },
        {
            "pattern": r"verify\s*=\s*False",
            "severity": "Medium",
            "title": "SSL verification disabled",
            "recommendation": (
                "Keep SSL certificate verification enabled."
            )
        },
        {
            "pattern": (
                r"(password|api_key|secret)\s*=\s*"
                r"['\"][^'\"]+['\"]"
            ),
            "severity": "Critical",
            "title": "Possible hardcoded secret",
            "recommendation": (
                "Move credentials into environment variables "
                "and rotate exposed secrets."
            )
        }
    ]

    findings = []

    for item in patterns:

        matches = re.finditer(
            item["pattern"],
            code,
            re.IGNORECASE
        )

        for match in matches:

            line_number = code[:match.start()].count("\n") + 1

            findings.append({
                "severity": item["severity"],
                "title": item["title"],
                "line": line_number,
                "recommendation": item["recommendation"]
            })

    return {
        "tool": "scan_security_patterns",
        "status": "completed",
        "findings": findings,
        "count": len(findings)
    }


# =====================================================
# 5. PYTHON ANALYSIS TOOL 3: IMPORT INSPECTOR
# =====================================================

def inspect_imports(code):

    try:

        tree = ast.parse(code)

        imports = []

        for node in ast.walk(tree):

            if isinstance(node, ast.Import):

                for item in node.names:
                    imports.append(item.name)

            elif isinstance(node, ast.ImportFrom):

                if node.module:
                    imports.append(node.module)

        return {
            "tool": "inspect_imports",
            "status": "completed",
            "imports": sorted(set(imports))
        }

    except SyntaxError:

        return {
            "tool": "inspect_imports",
            "status": "skipped",
            "imports": [],
            "message": "Could not inspect imports because syntax is invalid."
        }


# =====================================================
# 6. LOCAL FALLBACK REVIEW
# =====================================================

def create_local_fallback_review(tool_log):

    syntax = next(
        item for item in tool_log
        if item["tool"] == "check_python_syntax"
    )

    security = next(
        item for item in tool_log
        if item["tool"] == "scan_security_patterns"
    )

    imports = next(
        item for item in tool_log
        if item["tool"] == "inspect_imports"
    )

    lines = [
        "# PR Guardian AI - Local Review",
        "",
        "Gemini was unavailable. This report was generated "
        "using local Python static analysis tools.",
        "",
        "## 1. Overall Verdict",
        "",
        "Static analysis completed. Review the findings below "
        "before merging the code.",
        "",
        "## 2. Syntax Analysis",
        "",
        syntax["message"],
        "",
        "## 3. Security Findings",
        ""
    ]

    findings = security.get("findings", [])

    if findings:

        for finding in findings:

            lines.extend([
                f"### {finding['severity']}: {finding['title']}",
                f"- Line: {finding['line']}",
                f"- Recommendation: {finding['recommendation']}",
                ""
            ])

    else:

        lines.append(
            "No matching security patterns were detected."
        )

    lines.extend([
        "",
        "## 4. Imported Modules",
        "",
        ", ".join(imports.get("imports", []))
        or "No imports detected.",
        "",
        "## 5. Recommended Actions",
        "",
        "- Review flagged lines manually.",
        "- Avoid hardcoded credentials.",
        "- Validate untrusted inputs.",
        "- Run appropriate tests before merging.",
        "",
        "## 6. Final Risk Level",
        ""
    ])

    severities = [
        finding["severity"] for finding in findings
    ]

    if "Critical" in severities:
        risk = "CRITICAL"
    elif "High" in severities:
        risk = "HIGH"
    elif "Medium" in severities:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    lines.append(f"Detected risk level: {risk}")

    lines.extend([
        "",
        "Note: This is a basic static analysis prototype, "
        "not a complete security audit."
    ])

    return "\n".join(lines)


# =====================================================
# 7. GEMINI AI REVIEW
# =====================================================

def generate_gemini_review(code, analysis_results):

    client = get_gemini_client()

    if client is None:
        raise ValueError(
            "Gemini API key not found. Check your .env file."
        )

    prompt = f"""
You are PR Guardian AI, an expert Python code reviewer.

Review the submitted code using the analysis results.

RULES:
1. Do not claim the code was executed.
2. Do not invent vulnerabilities.
3. Explain the actual findings.
4. Prioritise security and correctness.
5. Give practical recommendations.
6. Distinguish confirmed findings from possible risks.
7. Keep the review clear and concise.

ANALYSIS RESULTS:

{json.dumps(analysis_results, indent=2)}

SUBMITTED PYTHON CODE:

```python
{code}
```

Generate a structured report with these sections:

## 1. Overall Verdict
## 2. Critical Issues
## 3. Security Findings
## 4. Code Quality Suggestions
## 5. Recommended Fixes
## 6. Final Risk Level

Explain why each important issue matters.
"""

    response = client.models.generate_content(
        model=MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.2,
            max_output_tokens=1200
        )
    )

    if not response.text:
        raise RuntimeError(
            "Gemini returned an empty response."
        )

    return response.text


# =====================================================
# 8. MAIN AGENT WORKFLOW
# =====================================================

def run_pr_guardian_agent(code):

    tool_log = []

    # Run local Python tools

    syntax_result = check_python_syntax(code)
    tool_log.append(syntax_result)

    security_result = scan_security_patterns(code)
    tool_log.append(security_result)

    imports_result = inspect_imports(code)
    tool_log.append(imports_result)

    # Collect results

    analysis_results = {
        "syntax_analysis": syntax_result,
        "security_analysis": security_result,
        "import_analysis": imports_result
    }

    # Ask Gemini for review

    try:

        review = generate_gemini_review(
            code,
            analysis_results
        )

        tool_log.append({
            "tool": "gemini_review",
            "status": "success",
            "message": "Gemini generated the code review."
        })

        review_source = "Gemini AI"

    except Exception as error:

        error_message = str(error)

        tool_log.append({
            "tool": "gemini_review",
            "status": "unavailable",
            "message": error_message[:500]
        })

        review = create_local_fallback_review(tool_log)

        review_source = "Local Python Fallback"

    return review, tool_log, review_source


# =====================================================
# 9. STREAMLIT USER INTERFACE
# =====================================================

st.title("🛡️ PR Guardian AI")

st.subheader(
    "AI-Powered Pull Request Reviewer"
)

st.write(
    "Review code using local Python analysis tools "
    "and Gemini-powered recommendations."
)


# About section

with st.expander("ℹ️ About the Agent"):

    st.markdown("""
    ### Agent workflow

    1. Receive submitted code.
    2. Execute Python analysis tools locally.
    3. Collect syntax, security and import findings.
    4. Send analysis results to Gemini.
    5. Generate an actionable code review.

    ### Python Tools

    - Syntax Checker
    - Security Pattern Scanner
    - Import Inspector

    ### Safety

    - Submitted code is never executed.
    - Static analysis only.
    - Use mock code for this prototype.
    - Do not submit secrets or personal data.
    """)


st.caption(f"Gemini model: {MODEL}")

st.caption(
    "Tool execution: Local Python analysis + Gemini review + local fallback"
)

st.divider()


# =====================================================
# 10. CODE INPUT
# =====================================================

st.header("Submit code for review")

default_code = '''import os

password = "admin123"

def calculate_total(price, quantity):
    result = eval("price * quantity")
    return result

print(calculate_total(100, 2))
'''

code = st.text_area(
    "Paste your Python code here",
    value=default_code,
    height=280,
    placeholder="Paste your Python code..."
)


# =====================================================
# 11. REVIEW BUTTON
# =====================================================

if st.button(
    "🔍 Review Code",
    type="primary",
    use_container_width=True
):

    if not code.strip():

        st.warning("Please enter some code first.")

    elif len(code) > 12000:

        st.error(
            "Please keep the submitted code under 12,000 characters."
        )

    else:

        with st.spinner(
            "Running Python tools and generating code review..."
        ):

            review, tool_log, review_source = (
                run_pr_guardian_agent(code)
            )

        # Status

        if review_source == "Gemini AI":

            st.success(
                "Gemini AI review completed successfully!"
            )

        else:

            st.warning(
                "Gemini is temporarily unavailable. "
                "Showing the local Python analysis report instead."
            )

        # Metrics

        security_result = next(
            item for item in tool_log
            if item["tool"] == "scan_security_patterns"
        )

        findings = security_result.get("findings", [])

        critical_count = sum(
            1 for item in findings
            if item["severity"] == "Critical"
        )

        high_count = sum(
            1 for item in findings
            if item["severity"] == "High"
        )

        medium_count = sum(
            1 for item in findings
            if item["severity"] == "Medium"
        )

        st.divider()

        st.header("📊 Analysis Summary")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Total Findings",
            len(findings)
        )

        col2.metric(
            "Critical",
            critical_count
        )

        col3.metric(
            "High",
            high_count
        )

        col4.metric(
            "Medium",
            medium_count
        )

        # Tool execution logs

        st.divider()

        st.header("🧰 Python Tool Execution")

        for result in tool_log:

            with st.expander(
                f"Tool: {result['tool']}",
                expanded=True
            ):

                st.json(result)

        # Final review

        st.divider()

        st.header("🤖 Code Review Report")

        st.caption(f"Review generated by: {review_source}")

        st.markdown(review)

        # Download report

        report = f"""
PR GUARDIAN AI
AI-POWERED CODE REVIEW

Model: {MODEL}
Review Source: {review_source}

====================================
PYTHON TOOL EXECUTION RESULTS
====================================

{json.dumps(tool_log, indent=2)}

====================================
FINAL CODE REVIEW
====================================

{review}

====================================
END OF REPORT
====================================
"""

        st.download_button(
            label="⬇️ Download Review Report",
            data=report,
            file_name="PR_Guardian_Review.txt",
            mime="text/plain",
            use_container_width=True
        )


# =====================================================
# 12. FOOTER
# =====================================================

st.divider()

st.caption(
    "PR Guardian AI | Hackathon Prototype | "
    "Static Analysis Only — Submitted Code Is Never Executed."
)
