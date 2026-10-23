"""
🛡️ HeaderShield — Website Security & HTTP Header Auditor
Author: HeaderShield Security Team
License: MIT
Description: Automated web security auditor for HTTP response headers, cookie flags,
             information leakage vectors, and server configuration hardening.
"""

import json
from datetime import datetime
from urllib.parse import urlparse
import requests
import streamlit as st
import pandas as pd

st.set_page_config(
    page_title="HeaderShield — Website Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .hs-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #10B981;
        margin-bottom: 0px;
    }
    .hs-subtitle {
        font-size: 1rem;
        color: #9CA3AF;
        margin-bottom: 25px;
    }
    .grade-box {
        font-size: 3.5rem;
        font-weight: 900;
        text-align: center;
        border-radius: 12px;
        padding: 10px;
        margin: 10px 0;
    }
    .grade-a { background: #064E3B; color: #34D399; border: 2px solid #059669; }
    .grade-b { background: #1E3A8A; color: #60A5FA; border: 2px solid #2563EB; }
    .grade-c { background: #78350F; color: #FBBF24; border: 2px solid #D97706; }
    .grade-d { background: #7C2D12; color: #FB923C; border: 2px solid #EA580C; }
    .grade-f { background: #7F1D1D; color: #F87171; border: 2px solid #DC2626; }
    .stDownloadButton>button {
        width: 100%;
        background-color: #059669;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# OWASP Recommended Security Headers Specifications
SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "weight": 20,
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "description": "Enforces secure (HTTPS) connections and prevents SSL stripping attacks.",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    {
        "name": "Content-Security-Policy",
        "weight": 25,
        "recommended": "default-src 'self'; script-src 'self' ...",
        "description": "Mitigates Cross-Site Scripting (XSS), data injection, and malicious frame embeds.",
        "owasp": "A03:2021-Injection"
    },
    {
        "name": "X-Frame-Options",
        "weight": 15,
        "recommended": "DENY or SAMEORIGIN",
        "description": "Protects users against Clickjacking attacks by preventing page framing.",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    {
        "name": "X-Content-Type-Options",
        "weight": 15,
        "recommended": "nosniff",
        "description": "Prevents MIME-type sniffing, forcing browsers to respect declared Content-Type.",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    {
        "name": "Referrer-Policy",
        "weight": 10,
        "recommended": "strict-origin-when-cross-origin",
        "description": "Governs how much referrer metadata is transmitted with HTTP requests.",
        "owasp": "A01:2021-Broken Access Control"
    },
    {
        "name": "Permissions-Policy",
        "weight": 10,
        "recommended": "geolocation=(), microphone=(), camera=()",
        "description": "Restricts browser features and hardware APIs (camera, mic, geo) from third-party embeds.",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "weight": 5,
        "recommended": "same-origin",
        "description": "Ensures a top-level document does not share a browsing context with cross-origin docs.",
        "owasp": "A05:2021-Security Misconfiguration"
    }
]

# Information Disclosure Headers to Flag
INFO_LEAK_HEADERS = [
    {"name": "Server", "risk": "Medium", "advice": "Exposes server software and version. Suppress in production."},
    {"name": "X-Powered-By", "risk": "High", "advice": "Leaks backend framework (PHP, Express, ASP.NET). Remove header."},
    {"name": "X-AspNet-Version", "risk": "High", "advice": "Discloses ASP.NET runtime version. Disable in web.config."},
    {"name": "X-Generator", "risk": "Medium", "advice": "Reveals CMS platform (WordPress, Drupal). Remove header."}
]


def audit_website(url: str):
    """Perform comprehensive HTTP header and security policy audit."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    headers_req = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 HeaderShield/1.0"
    }

    try:
        resp = requests.get(url, headers=headers_req, timeout=8, allow_redirects=True, verify=True)
    except requests.exceptions.SSLError:
        try:
            resp = requests.get(url, headers=headers_req, timeout=8, allow_redirects=True, verify=False)
        except Exception as e:
            return {"error": f"Failed to connect: {str(e)}"}
    except Exception as e:
        return {"error": f"Connection error: {str(e)}"}

    response_headers = {k.lower(): v for k, v in resp.headers.items()}

    # Check HTTPS redirect if input was http
    parsed = urlparse(url)
    https_enforced = resp.url.startswith("https://")

    # Audit Security Headers
    audit_results = []
    earned_score = 0
    total_weight = sum(h["weight"] for h in SECURITY_HEADERS)

    for item in SECURITY_HEADERS:
        h_key = item["name"].lower()
        present = h_key in response_headers
        val = response_headers.get(h_key, "")

        if present:
            earned_score += item["weight"]
            status = "Implemented"
        else:
            status = "Missing"

        audit_results.append({
            "header": item["name"],
            "status": status,
            "weight": item["weight"],
            "current_value": val if present else "None",
            "recommended": item["recommended"],
            "description": item["description"],
            "owasp": item["owasp"]
        })

    # Information Leaks
    leaks = []
    for info in INFO_LEAK_HEADERS:
        h_key = info["name"].lower()
        if h_key in response_headers:
            leaks.append({
                "header": info["name"],
                "value": response_headers[h_key],
                "risk": info["risk"],
                "advice": info["advice"]
            })
            earned_score = max(0, earned_score - 5)

    # Cookie Security
    cookies_audit = []
    for cookie in resp.cookies:
        c_flags = {
            "name": cookie.name,
            "secure": cookie.secure,
            "httponly": cookie.has_nonstandard_attr("httponly") or "httponly" in cookie._rest.keys(),
            "samesite": cookie.get_nonstandard_attr("samesite") or "Not Set"
        }
        cookies_audit.append(c_flags)

    # Score calculation & Letter Grade
    score_pct = int(round((earned_score / total_weight) * 100))
    score_pct = max(0, min(100, score_pct))

    if score_pct >= 90:
        grade = "A+"
        grade_css = "grade-a"
    elif score_pct >= 80:
        grade = "A"
        grade_css = "grade-a"
    elif score_pct >= 65:
        grade = "B"
        grade_css = "grade-b"
    elif score_pct >= 50:
        grade = "C"
        grade_css = "grade-c"
    elif score_pct >= 35:
        grade = "D"
        grade_css = "grade-d"
    else:
        grade = "F"
        grade_css = "grade-f"

    return {
        "url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "https_enforced": https_enforced,
        "score": score_pct,
        "grade": grade,
        "grade_css": grade_css,
        "audit_results": audit_results,
        "leaks": leaks,
        "cookies_audit": cookies_audit,
        "raw_headers": dict(resp.headers)
    }


# Sidebar
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=80)
st.sidebar.title("🛡️ HeaderShield")
st.sidebar.caption("Website Security & HTTP Auditor")
st.sidebar.markdown("---")
st.sidebar.markdown("""
### Security Checks:
- 🛡️ **OWASP Top Security Headers**
- 🍪 **Cookie Flag Hygiene (Secure/HttpOnly)**
- 🕵️ **Information Leakage Detection**
- 🔒 **HTTPS & Redirection Enforcement**
- 🛠️ **Nginx / Apache Config Fixes**
""")
st.sidebar.markdown("---")
st.sidebar.info("💡 **Why it matters**: Missing headers leave websites open to Clickjacking, Cross-Site Scripting (XSS), and session hijacking.")

# Main Header
st.markdown('<div class="hs-title">🛡️ HeaderShield — Website Security Auditor</div>', unsafe_allow_html=True)
st.markdown('<div class="hs-subtitle">Inspect HTTP response headers, identify information disclosures, and generate server hardening configurations</div>', unsafe_allow_html=True)

target_site = st.text_input("Enter Target Website URL:", value="https://example.com", help="e.g. https://github.com or https://example.com")

if st.button("🚀 Audit Website Security", type="primary"):
    with st.spinner("Connecting to target, auditing HTTP headers and cookie security flags..."):
        report = audit_website(target_site)

        if "error" in report:
            st.error(f"❌ {report['error']}")
        else:
            st.markdown("---")
            # Metrics & Grade Banner
            gcol, mcol1, mcol2, mcol3 = st.columns([1, 1, 1, 1])

            with gcol:
                st.markdown(f"""
                <div class="grade-box {report['grade_css']}">
                    {report['grade']}
                </div>
                """, unsafe_allow_html=True)
                st.caption(f"Security Posture Rating: **{report['score']} / 100**")

            with mcol1:
                st.metric("HTTP Status", f"{report['status_code']} OK" if report['status_code'] == 200 else str(report['status_code']))
            with mcol2:
                st.metric("HTTPS Enforced", "YES" if report['https_enforced'] else "NO", delta="Secure" if report['https_enforced'] else "Insecure", delta_color="normal" if report['https_enforced'] else "inverse")
            with mcol3:
                st.metric("Information Leaks", len(report['leaks']), delta=f"{len(report['leaks'])} detected" if report['leaks'] else "None", delta_color="inverse" if report['leaks'] else "normal")

            # Main Results Tabs
            tab_headers, tab_leaks, tab_cookies, tab_fix, tab_raw = st.tabs([
                "📋 Security Headers Audit",
                "🕵️ Information Disclosures",
                "🍪 Cookie Security Flags",
                "🛠️ Remediation Configs",
                "📜 Raw Headers"
            ])

            with tab_headers:
                st.markdown("### OWASP Recommended Security Headers")
                for h in report["audit_results"]:
                    with st.expander(f"{'✅' if h['status'] == 'Implemented' else '❌'} {h['header']} — {h['status']}"):
                        st.markdown(f"""
                        - **Description:** {h['description']}
                        - **OWASP Category:** `{h['owasp']}`
                        - **Current Value:** `{h['current_value']}`
                        - **Recommended Directive:** `{h['recommended']}`
                        """)

            with tab_leaks:
                if report["leaks"]:
                    st.error("🚨 Server Information Disclosures Detected! These headers give attackers intelligence about your tech stack.")
                    st.table(pd.DataFrame(report["leaks"]))
                else:
                    st.success("✅ No server version or technology disclosure headers detected (Server, X-Powered-By were sanitized).")

            with tab_cookies:
                if report["cookies_audit"]:
                    st.markdown("### Set-Cookie Security Attribute Evaluation")
                    st.table(pd.DataFrame(report["cookies_audit"]))
                else:
                    st.info("No cookies were set by the root URL during this request.")

            with tab_fix:
                st.markdown("### Ready-to-Copy Server Hardening Directives")
                st.markdown("#### Nginx Configuration (`/etc/nginx/nginx.conf` or `conf.d`):")
                nginx_config = """# HeaderShield Recommended Hardening Directives
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;

# Suppress Server Leaks
server_tokens off;"""
                st.code(nginx_config, language="nginx")

                st.markdown("#### Apache Configuration (`.htaccess` or `httpd.conf`):")
                apache_config = """# HeaderShield Recommended Apache Directives
<IfModule mod_headers.c>
    Header set X-Frame-Options "SAMEORIGIN"
    Header set X-Content-Type-Options "nosniff"
    Header set Referrer-Policy "strict-origin-when-cross-origin"
    Header set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header set Content-Security-Policy "default-src 'self';"
    Header unset X-Powered-By
    Header unset Server
</IfModule>
ServerSignature Off
ServerTokens Prod"""
                st.code(apache_config, language="apache")

            with tab_raw:
                st.json(report["raw_headers"])

            # Export Audit
            st.markdown("---")
            st.markdown("### 📑 Export Website Security Report")
            r1, r2 = st.columns(2)

            r1.download_button(
                "📥 Download JSON Security Audit",
                data=json.dumps(report, indent=4),
                file_name=f"headershield_{urlparse(target_site).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

            md_audit = f"""# HeaderShield Website Security Audit
**Target URL:** {report['url']}
**Resolved URL:** {report['final_url']}
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Security Grade:** {report['grade']} ({report['score']} / 100)

## Security Headers Status
| Header | Status | Current Value | Recommended |
|---|---|---|---|
"""
            for h in report["audit_results"]:
                md_audit += f"| {h['header']} | {h['status']} | `{h['current_value']}` | `{h['recommended']}` |\n"

            md_audit += "\n## Information Disclosures\n"
            if report["leaks"]:
                for l in report["leaks"]:
                    md_audit += f"- **{l['header']}**: `{l['value']}` (Risk: {l['risk']}) - {l['advice']}\n"
            else:
                md_audit += "None detected.\n"

            r2.download_button(
                "📥 Download Markdown Audit Report",
                data=md_audit,
                file_name=f"headershield_{urlparse(target_site).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown"
            )
