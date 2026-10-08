import streamlit as st
from urllib.parse import urlparse
import re

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide"
)

if "history" not in st.session_state:
    st.session_state.history = []

st.sidebar.title("🛡️ PhishGuard")
st.sidebar.write("Phishing URL Detection & Cybersecurity Awareness")

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Dashboard",
        "🔍 URL Scanner",
        "📋 Analysis History",
        "🔐 Cybersecurity Awareness",
        "ℹ️ About Project"
    ]
)

st.sidebar.divider()
st.sidebar.info(
    "PhishGuard analyzes common URL characteristics "
    "to identify potential phishing indicators."
)


# =========================
# DASHBOARD
# =========================

if page == "🏠 Dashboard":

    st.markdown(
        """
        <div style="
            padding: 35px;
            border-radius: 18px;
            background: linear-gradient(135deg, #0f172a, #1e3a5f);
            margin-bottom: 25px;
        ">
            <h1 style="color:white; margin-bottom:10px;">
                🛡️ PhishGuard
            </h1>
            <h3 style="color:#dbeafe;">
                Phishing URL Detection & Cybersecurity Awareness System
            </h3>
            <p style="color:#cbd5e1; font-size:17px;">
                Analyze website URLs, identify common phishing indicators,
                and improve your cybersecurity awareness.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.subheader("🔎 What Does PhishGuard Do?")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.info(
            "🌐 **URL Analysis**\n\n"
            "Analyzes different characteristics of website URLs "
            "to identify potential warning signs."
        )

    with col2:
        st.success(
            "📊 **Risk Scoring**\n\n"
            "Uses predefined security rules to calculate "
            "a risk score from 0 to 10."
        )

    with col3:
        st.warning(
            "🛡️ **Cyber Awareness**\n\n"
            "Provides simple cybersecurity tips to help users "
            "recognize and avoid phishing attacks."
        )

    st.divider()

    st.subheader("📊 Understanding the Risk Score")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.success("🟢 LOW RISK\n\n0–2 indicators detected.")

    with col2:
        st.warning("🟠 SUSPICIOUS\n\n3–4 indicators detected.")

    with col3:
        st.error("🔴 HIGH RISK\n\n5–10 indicators detected.")

    st.divider()

    st.subheader("🔍 Detection Features")

    feature_col1, feature_col2 = st.columns(2)

    with feature_col1:
        st.write("✅ HTTPS verification")
        st.write("✅ URL length analysis")
        st.write("✅ @ symbol detection")
        st.write("✅ Subdomain analysis")
        st.write("✅ IP address detection")

    with feature_col2:
        st.write("✅ Special character analysis")
        st.write("✅ Suspicious keyword detection")
        st.write("✅ Multiple hyphen detection")
        st.write("✅ URL shortener detection")
        st.write("✅ Suspicious URL word detection")

    st.divider()

    st.subheader("⚠️ Important Security Notice")

    st.warning(
        "PhishGuard is a rule-based risk indicator system. "
        "A LOW RISK result does not guarantee that a website is completely safe, "
        "and a HIGH RISK result does not prove that a website is malicious. "
        "Always verify websites before entering sensitive information."
    )

    st.divider()

    st.caption("PhishGuard | Cybersecurity Awareness & URL Analysis")


# =========================
# URL SCANNER
# =========================

elif page == "🔍 URL Scanner":

    st.title("🛡️ PhishGuard")
    st.subheader("Phishing URL Detection System")

    st.write(
        "Check a website URL for common phishing indicators "
        "using a rule-based risk analysis system."
    )

    st.divider()

    url = st.text_input(
        "🌐 Enter Website URL",
        placeholder="https://example.com"
    )

    check_button = st.button(
        "🔍 Analyze URL",
        use_container_width=True
    )

    if check_button:

        if not url:
            st.warning("⚠️ Please enter a website URL.")

        else:

            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            parsed_url = urlparse(url)
            hostname = parsed_url.hostname or ""

            score = 0
            warnings = []

            # 1. HTTPS
            if parsed_url.scheme != "https":
                score += 1
                warnings.append(
                    "The website does not use HTTPS."
                )

            # 2. URL length
            if len(url) > 75:
                score += 1
                warnings.append(
                    "The URL is unusually long."
                )

            # 3. @ symbol
            if "@" in url:
                score += 1
                warnings.append(
                    "The URL contains an @ symbol."
                )

            # 4. Many subdomains
            if hostname.count(".") > 3:
                score += 1
                warnings.append(
                    "The domain contains many subdomains."
                )

            # 5. IP address
            if re.fullmatch(
                r"\d+\.\d+\.\d+\.\d+",
                hostname
            ):
                score += 1
                warnings.append(
                    "The website uses an IP address instead of a domain name."
                )

            # 6. Special characters
            special_characters = ["-", "_", "%"]

            special_count = sum(
                url.count(char)
                for char in special_characters
            )

            if special_count >= 4:
                score += 1
                warnings.append(
                    "The URL contains an unusually high number of special characters."
                )

            # 7. Suspicious keywords
            suspicious_words = [
                "verify",
                "password",
                "account",
                "signin",
                "confirm",
                "wallet",
                "login",
                "secure",
                "update"
            ]

            found_words = []

            for word in suspicious_words:
                if word in url.lower():
                    found_words.append(word)

            if found_words:
                score += 1
                warnings.append(
                    "The URL contains potentially suspicious keywords such as: "
                    + ", ".join(found_words)
                )

            # 8. Multiple hyphens
            if hostname.count("-") >= 3:
                score += 1
                warnings.append(
                    "The domain contains multiple hyphens, "
                    "which can be used in deceptive domains."
                )

            # 9. URL shorteners
            shortener_domains = [
                "bit.ly",
                "tinyurl.com",
                "t.co",
                "goo.gl",
                "ow.ly",
                "is.gd"
            ]

            if hostname.lower() in shortener_domains:
                score += 1
                warnings.append(
                    "The URL uses a shortened link, "
                    "which can hide the final destination."
                )

            # 10. Suspicious promotional words
            suspicious_url_words = [
                "free",
                "bonus",
                "claim",
                "prize",
                "urgent",
                "click"
            ]

            found_url_words = []

            for word in suspicious_url_words:
                if word in url.lower():
                    found_url_words.append(word)

            if found_url_words:
                score += 1
                warnings.append(
                    "The URL contains words commonly used "
                    "in suspicious or misleading links."
                )

            # Risk classification
            if score <= 2:
                risk_level = "🟢 LOW RISK"

            elif score <= 4:
                risk_level = "🟠 SUSPICIOUS"

            else:
                risk_level = "🔴 HIGH RISK"

            # Save history
            st.session_state.history.append(
                {
                    "URL": url,
                    "Score": f"{score} / 10",
                    "Result": risk_level
                }
            )

            st.divider()

            st.subheader("📊 Risk Analysis")

            col1, col2 = st.columns(2)

            with col1:
                st.metric(
                    "Risk Score",
                    f"{score} / 10"
                )

            with col2:
                st.metric(
                    "Risk Level",
                    risk_level
                )

            if score <= 2:

                st.success(
                    "🟢 LOW RISK — Few common phishing indicators were detected."
                )

            elif score <= 4:

                st.warning(
                    "🟠 SUSPICIOUS URL — Some warning signs were detected."
                )

            else:

                st.error(
                    "🔴 HIGH RISK — Multiple potential phishing indicators were detected."
                )

            if warnings:

                st.subheader("⚠️ Warning Signs")

                for warning in warnings:
                    st.write("• " + warning)

            else:

                st.info(
                    "No common warning signs were detected."
                )

            st.subheader("🛡️ Safety Recommendation")

            if score >= 3:

                st.write(
                    "Avoid entering passwords, financial details, "
                    "or personal information until you verify "
                    "that the website is legitimate."
                )

            else:

                st.write(
                    "The URL shows few common warning signs, "
                    "but always verify the website before entering "
                    "sensitive information."
                )

            st.caption(
                "Note: This tool provides a rule-based risk indication "
                "and does not guarantee that a website is safe or malicious."
            )


# =========================
# HISTORY
# =========================

elif page == "📋 Analysis History":

    st.title("📋 Analysis History")

    st.write(
        "URLs analyzed during the current session."
    )

    st.divider()

    if st.session_state.history:

        for number, item in enumerate(
            reversed(st.session_state.history),
            start=1
        ):

            st.write(
                f"**{number}. {item['URL']}**"
            )

            col1, col2 = st.columns(2)

            with col1:
                st.write(
                    f"Risk Score: **{item['Score']}**"
                )

            with col2:
                st.write(
                    f"Result: **{item['Result']}**"
                )

            st.divider()

        if st.button("🗑️ Clear History"):

            st.session_state.history = []

            st.success(
                "History cleared."
            )

    else:

        st.info(
            "No URLs have been analyzed yet."
        )


# =========================
# CYBERSECURITY AWARENESS
# =========================

elif page == "🔐 Cybersecurity Awareness":

    st.title("🔐 Cybersecurity Awareness")

    st.write(
        "Learn simple ways to protect yourself from phishing "
        "and other common cybersecurity threats."
    )

    st.divider()

    with st.expander(
        "🎣 How to Identify a Phishing Link"
    ):

        st.write(
            "• Check the website address carefully."
        )

        st.write(
            "• Look for unusual spelling or suspicious domains."
        )

        st.write(
            "• Be careful with links asking for passwords "
            "or personal information."
        )

        st.write(
            "• Do not click links from unknown or unexpected messages."
        )

    with st.expander(
        "🔐 Password Safety"
    ):

        st.write(
            "• Use strong and unique passwords."
        )

        st.write(
            "• Do not reuse passwords for important accounts."
        )

        st.write(
            "• Enable multi-factor authentication whenever possible."
        )

        st.write(
            "• Never share passwords through messages or email."
        )

    with st.expander(
        "🌐 Safe Browsing Tips"
    ):

        st.write(
            "• Keep your browser and operating system updated."
        )

        st.write(
            "• Avoid downloading files from unknown websites."
        )

        st.write(
            "• Check website addresses before entering sensitive information."
        )

        st.write(
            "• Be careful when using unknown public Wi-Fi networks."
        )

    with st.expander(
        "🚨 What If You Clicked a Phishing Link?"
    ):

        st.write(
            "1. Do not enter personal or financial information."
        )

        st.write(
            "2. Close the suspicious website."
        )

        st.write(
            "3. Change your password if you entered it."
        )

        st.write(
            "4. Enable multi-factor authentication."
        )

        st.write(
            "5. Contact your bank if financial information was shared."
        )


# =========================
# ABOUT PROJECT
# =========================

else:

    st.title("ℹ️ About PhishGuard")

    st.subheader(
        "Phishing URL Detection and Cybersecurity Awareness System"
    )

    st.write(
        "PhishGuard is a cybersecurity awareness project designed "
        "to identify common characteristics associated with "
        "potential phishing URLs."
    )

    st.write(
        "The system uses a rule-based scoring mechanism to analyze "
        "different URL characteristics and generate a risk level."
    )

    st.divider()

    st.subheader("🔎 Detection Features")

    st.write("• HTTPS verification")
    st.write("• URL length analysis")
    st.write("• @ symbol detection")
    st.write("• Subdomain analysis")
    st.write("• IP address detection")
    st.write("• Special character analysis")
    st.write("• Suspicious keyword detection")
    st.write("• Multiple hyphen detection")
    st.write("• URL shortener detection")
    st.write("• Suspicious URL word detection")

    st.divider()

    st.subheader("🎓 Project Relevance")

    st.write(
        "This project is related to concepts covered in the "
        "Cisco Introduction to Cybersecurity course, including "
        "phishing, attacks, data protection, privacy, "
        "and organizational security."
    )

    st.divider()

    st.caption(
        "PhishGuard | Cybersecurity Awareness & URL Analysis"
    )