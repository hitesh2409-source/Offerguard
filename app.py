import html
import re
from datetime import datetime, timezone
from urllib.parse import quote_plus

import requests
import streamlit as st

# ============================================================
# PART 1A: SCAM WORD RULES
# Each rule has: a name, words/phrases to look for,
# points to add if found, and a plain-language reason.
# To add a new rule later, just copy one block and edit it.
# ============================================================
RULES = [
    {
        "name": "Asks for money",
        "keywords": ["registration fee", "security deposit", "deposit", "processing fee",
                     "training fee", "kit fee", "pay rs", "send money"],
        "points": 40,
        "reason": "Genuine internships do not charge you. Asking for money is the biggest warning sign.",
    },
    {
        "name": "Asks for sensitive details",
        "keywords": ["aadhaar", "aadhar", "pan card", "bank account", "otp", "cvv",
                     "password", "atm pin"],
        "points": 35,
        "reason": "Real companies do not ask for these details before you have joined.",
    },
    {
        "name": "Too good to be true",
        "keywords": ["guaranteed job", "100% placement", "no experience required",
                     "earn per day", "easy money", "work from home and earn"],
        "points": 25,
        "reason": "Big promises with little work are a common trick.",
    },
    {
        "name": "Pressure to act fast",
        "keywords": ["urgent", "immediately", "limited seats", "last chance",
                     "within 24 hours", "today only", "hurry"],
        "points": 20,
        "reason": "Scammers rush you so you do not have time to check.",
    },
    {
        "name": "Hired without an interview",
        "keywords": ["no interview", "without interview", "directly selected"],
        "points": 20,
        "reason": "Real companies almost always interview or test you first.",
    },
    {
        "name": "Chat-app only contact",
        "keywords": ["whatsapp", "telegram"],
        "points": 15,
        "reason": "Official offers usually come from a company email, not only a chat app.",
    },
]

# ============================================================
# PART 1B: MISSING DETAILS
# A real offer usually mentions these things. If the message
# has NONE of the keywords or patterns, we add the points.
# ============================================================
EMAIL_PATTERN = r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
LINK_PATTERN = r"https?://\S+|\bwww\.\S+"

DETAIL_CHECKS = [
    {
        "name": "No role mentioned",
        "keywords": ["intern", "internship", "trainee", "developer", "engineer", "analyst",
                     "designer", "associate", "executive", "role", "position"],
        "patterns": [],
        "points": 10,
        "reason": "The message never says what job or role you are being offered.",
    },
    {
        "name": "No duration mentioned",
        "keywords": ["duration", "tenure", "semester", "summer"],
        "patterns": [r"\b(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)\s*(?:-|to|–)?\s*(?:\d+\s*)?(?:day|week|month|year)s?\b",
                     r"\b(?:from|starting)\b.{0,40}\b(?:to|till|until|through)\b"],
        "points": 5,
        "reason": "Real offers say how long the internship or job lasts.",
    },
    {
        "name": "No pay information",
        "keywords": ["stipend", "salary", "ctc", "lpa", "unpaid", "paid", "compensation",
                     "per month", "per annum"],
        "patterns": [],
        "points": 5,
        "reason": "Real offers say whether the role is paid or unpaid.",
    },
    {
        "name": "No work location or mode",
        "keywords": ["remote", "onsite", "on-site", "hybrid", "office", "location",
                     "work from home", "wfh", "virtual", "campus"],
        "patterns": [],
        "points": 5,
        "reason": "Real offers say where or how you will work.",
    },
    {
        "name": "No company email or website",
        "keywords": [],
        "patterns": [EMAIL_PATTERN, LINK_PATTERN],
        "points": 10,
        "reason": "There is no email or website you could use to check the company.",
    },
]

# ============================================================
# PART 1C: SENDER EMAIL SETTINGS
# ============================================================
FREE_EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com",
                      "live.com", "rediffmail.com", "ymail.com", "icloud.com",
                      "proton.me", "protonmail.com"]

# Words in a company name that we ignore when comparing to the email domain
IGNORE_WORDS = ["pvt", "ltd", "limited", "private", "inc", "llp", "corp", "company",
                "technologies", "solutions", "services", "innovations", "india",
                "the", "and"]


# ============================================================
# PART 2: THE LOGIC (no website code here)
# ============================================================
def has_phrase(text, phrase):
    """True if the phrase appears as a whole word or phrase.
    (So 'otp' will not match inside the word 'hotpot'.)"""
    pattern = r"\b" + re.escape(phrase) + r"\b"
    return re.search(pattern, text) is not None


def detail_present(text, check):
    """True if the message contains this detail (a keyword or a pattern)."""
    for word in check["keywords"]:
        if has_phrase(text, word):
            return True
    for pattern in check["patterns"]:
        if re.search(pattern, text):
            return True
    return False


def get_domain(email):
    """Return the part after @ , or None if it is not a valid email."""
    match = re.fullmatch(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", email.strip().lower())
    return match.group(1) if match else None


def check_sender(sender, company):
    """Check the sender's email. Returns a list of warnings."""
    results = []
    sender = sender.strip().lower()
    if sender == "":
        return results

    domain = get_domain(sender)
    if domain is None:
        results.append({
            "group": "Sender check", "name": "Email address looks invalid", "points": 10,
            "reason": "The sender address is not a properly formed email.",
            "found": [sender],
        })
        return results

    if domain in FREE_EMAIL_DOMAINS:
        results.append({
            "group": "Sender check", "name": "Free email provider used", "points": 25,
            "reason": "Companies normally email from their own domain, not a free service. "
                      "A few small startups do use free email, so verify before trusting it.",
            "found": [domain],
        })
    elif company.strip() != "":
        words = re.findall(r"[a-z0-9]+", company.lower())
        words = [w for w in words if len(w) >= 3 and w not in IGNORE_WORDS]
        domain_text = domain.replace("-", "").replace(".", "")
        if words and not any(w in domain_text for w in words):
            results.append({
                "group": "Sender check", "name": "Email domain does not match company name",
                "points": 15,
                "reason": "The email domain does not clearly match the company name. "
                          "Check the company's official website for its real email domain.",
                "found": [domain],
            })
    return results


def root_domain(domain):
    """mail.company.co.in -> company.co.in  (simple version)"""
    parts = domain.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ["co", "com", "org", "net", "ac", "gov", "edu", "nic"]:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


@st.cache_data(ttl=3600, show_spinner=False)
def lookup_domain_age(domain):
    """Ask the free RDAP service when a domain was registered.
    Returns the age in days, or None if we could not find out."""
    try:
        r = requests.get("https://rdap.org/domain/" + domain, timeout=8,
                         headers={"Accept": "application/rdap+json"})
        if r.status_code != 200:
            return None
        for event in r.json().get("events", []):
            if event.get("eventAction") == "registration":
                date = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                if date.tzinfo is None:
                    date = date.replace(tzinfo=timezone.utc)
                return (datetime.now(timezone.utc) - date).days
    except Exception:
        return None
    return None


@st.cache_data(ttl=3600, show_spinner=False)
def lookup_mail_dns(domain):
    """Ask Google's free DNS service if the domain exists and can get email.
    Returns 'ok', 'no_domain', 'no_mail' or 'unknown'."""
    try:
        for record_type in ["MX", "A"]:
            r = requests.get("https://dns.google/resolve",
                             params={"name": domain, "type": record_type}, timeout=8)
            data = r.json()
            if data.get("Status") == 3:
                return "no_domain"
            if data.get("Answer"):
                return "ok"
        return "no_mail"
    except Exception:
        return "unknown"


def check_domain(domain):
    """Live checks on the sender's domain. Returns a list of findings."""
    results = []

    dns = lookup_mail_dns(domain)
    if dns == "no_domain":
        results.append({
            "group": "Sender check", "name": "Domain does not exist", "points": 30,
            "reason": "The sender's domain has no DNS records at all, so it is probably fake.",
            "found": [domain],
        })
    elif dns == "no_mail":
        results.append({
            "group": "Sender check", "name": "Domain cannot receive email", "points": 15,
            "reason": "The domain exists but has no mail records, which is unusual for a real company.",
            "found": [domain],
        })

    age = lookup_domain_age(root_domain(domain))
    if age is None:
        results.append({
            "group": "Sender check", "name": "Domain age could not be checked", "points": 0,
            "reason": "The registry did not return a registration date. This is common for some "
                      "domain endings, so it does not count against the offer.",
            "found": [domain],
        })
    elif age < 30:
        results.append({
            "group": "Sender check", "name": f"Domain is only {age} days old", "points": 35,
            "reason": "Scam websites are often created days before they are used. Real companies "
                      "usually have older domains.",
            "found": [domain],
        })
    elif age < 90:
        results.append({
            "group": "Sender check", "name": f"Domain is only {age} days old", "points": 20,
            "reason": "The domain was registered recently. Check that the company really exists.",
            "found": [domain],
        })
    elif age < 180:
        results.append({
            "group": "Sender check", "name": f"Domain is {age} days old", "points": 10,
            "reason": "The domain is fairly new. Not a problem by itself, but verify the company.",
            "found": [domain],
        })
    else:
        results.append({
            "group": "Sender check", "name": f"Domain is about {age // 365} year(s) old"
            if age >= 365 else f"Domain is {age} days old", "points": 0,
            "reason": "An older domain is a good sign, but scammers can also hijack or buy old domains.",
            "found": [domain],
        })
    return results


def check_message(message, sender="", company="", live=True):
    """Look at everything and return (score, list of warnings)."""
    text = message.lower()
    score = 0
    matches = []

    # 1) Scam words
    for rule in RULES:
        found = [p for p in rule["keywords"] if has_phrase(text, p)]
        if found:
            matches.append({
                "group": "Warning signs", "name": rule["name"],
                "points": rule["points"], "reason": rule["reason"], "found": found,
            })

    # 2) Missing details
    for check in DETAIL_CHECKS:
        if not detail_present(text + " " + sender.lower(), check):
            matches.append({
                "group": "Missing details", "name": check["name"],
                "points": check["points"], "reason": check["reason"], "found": [],
            })

    # 3) Sender email (use the box, or the first email found in the message)
    if sender.strip() == "":
        emails_in_message = re.findall(EMAIL_PATTERN, text)
        if emails_in_message:
            sender = emails_in_message[0]
    matches += check_sender(sender, company)

    # 4) Live checks on the sender's domain (needs internet)
    domain = get_domain(sender)
    if live and domain and domain not in FREE_EMAIL_DOMAINS:
        matches += check_domain(domain)

    for m in matches:
        score += m["points"]
    score = min(score, 100)
    return score, matches


def risk_level(score):
    """Turn a number into Low / Medium / High."""
    if score >= 50:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


# ============================================================
# PART 3A: BUILDING THE PRETTY HTML PIECES (no Streamlit calls)
# ============================================================
LEVEL_COLORS = {"Low": "#1fa971", "Medium": "#f5a524", "High": "#e03e5a"}
GROUP_COLORS = {"Warning signs": "#e03e5a", "Missing details": "#f5a524", "Sender check": "#6c4cf1"}
GROUP_CLASS = {"Warning signs": "w", "Missing details": "m", "Sender check": "s"}
SUMMARY = {
    "High": "Several strong warning signs. Do not pay or share documents.",
    "Medium": "Some warning signs or missing details. Cross-check before replying.",
    "Low": "Few warning signs found. Use the cross-check links to confirm the company.",
}
FIELDS = {
    "Any": "internship",
    "Tech": "software developer intern",
    "Design": "graphic design intern",
    "Marketing": "digital marketing intern",
    "Data": "data analyst intern",
    "Finance": "finance intern",
}
EXAMPLES = [
    "Congratulations! You are selected for our Data Entry internship. Pay a registration fee of "
    "Rs 500 immediately to confirm your seat. Limited seats, last chance. Contact us on WhatsApp.",
    "Please confirm your acceptance and availability for the proposed joining date.\n\n"
    "We look forward to your response and wish you success in your professional journey.\n\n"
    "Regards,\nHuman Resources Department\nTechNova Innovations",
    "Dear Candidate, we are pleased to offer you a 2 month internship as a Python developer at our "
    "Gurugram office. The stipend is Rs 10000 per month. Please reply to hr@technova.com with your "
    "joining date. More about us: https://technova.com/careers",
]

CSS = """
<style>
footer, [data-testid="stToolbar"] {visibility: hidden;}
[data-testid="stHeader"] {background: transparent;}
.block-container, [data-testid="stMainBlockContainer"] {max-width: 780px; padding-top: 4.5rem !important;}
[data-testid="stAppViewContainer"] {
  background-image: radial-gradient(520px 320px at 92% 0, rgba(255,143,171,.25), transparent),
                    radial-gradient(520px 360px at 0 8%, rgba(142,197,255,.28), transparent);}
.og-title {font-size: 2.3rem; font-weight: 800; margin: 0; line-height: 1.2;}
.og-title span {color: #6c4cf1;}
.og-sub {opacity: .75; margin: 4px 0 14px;}
.og-card {border: 1px solid rgba(128,128,128,.28); border-radius: 20px; padding: 16px 18px;
  margin: 10px 0; background: rgba(255,255,255,.55); box-shadow: 0 8px 26px rgba(108,76,241,.08);}
.og-badge {display: inline-block; padding: 6px 20px; border-radius: 999px; font-weight: 800; font-size: 1.3rem;}
.og-f {border-left: 5px solid #888; border-radius: 12px; padding: 8px 12px; margin: 10px 0;
  background: rgba(128,128,128,.08);}
.og-f b {display: flex; justify-content: space-between; gap: 8px;}
.og-f small {opacity: .75; display: block;}
.og-bar {height: 5px; border-radius: 5px; margin-top: 6px; opacity: .85;}
mark {background: #ffe58a; color: #2b2540; border-radius: 5px; padding: 0 3px;}
@keyframes og-fill {from {stroke-dashoffset: 141.4;}}
div[data-testid="stElementContainer"]:has(button), div[data-testid="stElementContainer"]:has(a[data-testid^="stBaseLinkButton"]) {width: 100% !important;}
div.stButton, div.stDownloadButton, div[data-testid="stButton"], div[data-testid="stDownloadButton"] {width: 100% !important;}
div.stButton > button, div.stDownloadButton > button, div[data-testid="stButton"] > button, div[data-testid="stDownloadButton"] > button {width: 100%; border-radius: 999px; font-weight: 700;}
button[data-testid="stBaseButton-primary"] {background-color: #6c4cf1 !important; border-color: #6c4cf1 !important; color: #fff !important;}
a[data-testid^="stBaseLinkButton"] {width: 100%; justify-content: center; border-radius: 999px; font-weight: 700;}
</style>
"""


def gauge_html(score, level):
    color = LEVEL_COLORS[level]
    offset = 141.4 * (1 - score / 100)
    return (
        '<div class="og-card" style="text-align:center">'
        '<svg viewBox="0 0 110 65" style="width:240px;max-width:75%">'
        '<path d="M10 55 A45 45 0 0 1 100 55" fill="none" stroke="rgba(128,128,128,.25)" '
        'stroke-width="11" stroke-linecap="round"/>'
        f'<path d="M10 55 A45 45 0 0 1 100 55" fill="none" stroke="{color}" stroke-width="11" '
        f'stroke-linecap="round" stroke-dasharray="141.4" stroke-dashoffset="{offset:.1f}" '
        'style="animation: og-fill 1s ease-out"/></svg>'
        f'<div style="font-size:2.3rem;font-weight:800;line-height:1">{score}</div>'
        f'<div class="og-badge" style="background:{color}22;color:{color}">{level} risk</div>'
        f'<div style="opacity:.75;margin-top:8px">{SUMMARY[level]}</div></div>'
    )


def finding_html(m):
    color = GROUP_COLORS[m["group"]]
    cls = GROUP_CLASS[m["group"]]
    found = ""
    if m["found"]:
        found = "<small>Found: " + html.escape(", ".join(m["found"])) + "</small>"
    width = max(6, m["points"] * 2.5)
    return (
        f'<div class="og-f {cls}" style="border-color:{color}">'
        f'<b><span>{html.escape(m["name"])}</span><span>+{m["points"]}</span></b>'
        f'<div style="opacity:.85;font-size:.93rem">{html.escape(m["reason"])}</div>{found}'
        f'<div class="og-bar" style="width:{width}%;background:{color}"></div></div>'
    )


def highlight_html(message, words):
    text = html.escape(message)
    for w in sorted(set(words), key=len, reverse=True):
        pattern = r"\b" + re.escape(html.escape(w)) + r"\b"
        text = re.sub(pattern, lambda m: "<mark>" + m.group(0) + "</mark>", text, flags=re.IGNORECASE)
    return ('<div class="og-card" style="word-break:break-word">'
            + text.replace("\n", "<br>") + "</div>")


def guess_field(message):
    t = message.lower()
    if re.search(r"develop|engineer|python|java|software|web|coding", t):
        return "Tech"
    if re.search(r"design|graphic|\bui\b|\bux\b", t):
        return "Design"
    if re.search(r"market|social media|content", t):
        return "Marketing"
    if re.search(r"data|analyst", t):
        return "Data"
    if re.search(r"financ|account", t):
        return "Finance"
    return "Any"


def link_domain(sender, message):
    """The domain to look up: from the sender's email, or the first link in the message."""
    d = get_domain(sender) if sender.strip() else None
    if d:
        return d
    found = re.search(r"(?:https?://|www\.)([\w.-]+\.[a-z]{2,})", message, re.IGNORECASE)
    if found:
        return found.group(1).lower().removeprefix("www.")
    emails = re.findall(EMAIL_PATTERN, message.lower())
    return get_domain(emails[0]) if emails else None


def google(q):
    return "https://www.google.com/search?q=" + quote_plus(q)


def crosscheck_links(company, domain):
    """Returns a list of (heading, [(label, url), ...])."""
    groups = []
    company = company.strip()
    if company:
        q = quote_plus(company)
        groups.append(("Does the company exist?", [
            ("Official website", google(company + " official website")),
            ("LinkedIn page", "https://www.linkedin.com/search/results/companies/?keywords=" + q),
            ("Registration details", google(company + " company registration MCA")),
            ("Employee reviews", google(company + " reviews glassdoor ambitionbox")),
        ]))
        groups.append(("Any scam reports?", [
            ("Scam reports", google(company + " internship scam")),
            ("Fake offer complaints", google(company + " fake offer letter complaint")),
        ]))
    if domain and domain not in FREE_EMAIL_DOMAINS:
        dm = quote_plus(domain)
        groups.append((f"Is {domain} safe, and how old is it?", [
            ("Domain age (ICANN)", "https://lookup.icann.org/en/lookup?name=" + dm),
            ("ScamAdviser", "https://www.scamadviser.com/check-website/" + dm),
            ("VirusTotal", "https://www.virustotal.com/gui/domain/" + dm),
            ("Google Safe Browsing", "https://transparencyreport.google.com/safe-browsing/search?url=" + dm),
        ]))
    elif domain:
        groups.append((f"The sender uses a free email ({domain})", [
            ("How to check this", google("how to check if a company hr email on gmail is fake")),
        ]))
    groups.append(("Already paid or shared documents?", [
        ("Report on cybercrime.gov.in", "https://cybercrime.gov.in"),
    ]))
    return groups


def genuine_links(field):
    kw = FIELDS[field]
    platforms = [
        ("LinkedIn", "https://www.linkedin.com/jobs/search/?keywords=" + quote_plus(kw)),
        ("Internshala", google("site:internshala.com " + kw)),
        ("Unstop", google("site:unstop.com " + kw)),
        ("Naukri", google("site:naukri.com " + kw)),
    ]
    official = [
        ("PM Internship Scheme", "https://pminternship.mca.gov.in"),
        ("Apprenticeship India", "https://www.apprenticeshipindia.gov.in"),
        ("National Career Service", "https://www.ncs.gov.in"),
        ("AICTE Internship Portal", "https://internship.aicte-india.org"),
    ]
    return platforms, official


def report_text(level, score, matches, message):
    lines = ["OFFERGUARD REPORT", f"Risk: {level} ({score}/100)", ""]
    for m in matches:
        lines.append(f"- {m['name']} (+{m['points']}): {m['reason']}")
    lines += ["", "Message checked:", message, "",
              "This shows warning signs, not a verdict. Cross-check the company before trusting an offer."]
    return "\n".join(lines)


# ============================================================
# PART 3B: THE WEBSITE
# ============================================================
st.set_page_config(page_title="OfferGuard", page_icon="🛡️", layout="centered")
st.markdown(CSS, unsafe_allow_html=True)

for key, default in [("msg", ""), ("sender", ""), ("company", ""), ("result", None),
                     ("history", []), ("field", "Any")]:
    if key not in st.session_state:
        st.session_state[key] = default


def load_example(i):
    st.session_state.msg = EXAMPLES[i]
    st.session_state.sender = ""
    st.session_state.company = "TechNova Innovations" if i == 2 else ""
    st.session_state.go = True


def load_history(i):
    item = st.session_state.history[i]
    st.session_state.msg = item["msg"]
    st.session_state.sender = item["sender"]
    st.session_state.company = item["company"]
    st.session_state.go = True


def clear_all():
    st.session_state.msg = ""
    st.session_state.sender = ""
    st.session_state.company = ""
    st.session_state.result = None


# ---------- Header ----------
st.markdown('<p class="og-title">🛡️ Offer<span>Guard</span></p>'
            '<p class="og-sub">Paste an internship or job offer. Get a risk score, the exact red flags, '
            'and where to cross-check them.</p>', unsafe_allow_html=True)

# ---------- Input card ----------
st.caption("Try an example")
ex1, ex2, ex3 = st.columns(3)
ex1.button("🚩 Fee scam", on_click=load_example, args=(0,))
ex2.button("🤔 Polite but vague", on_click=load_example, args=(1,))
ex3.button("✅ Genuine offer", on_click=load_example, args=(2,))

with st.container(border=True):
    st.text_area("Offer message", key="msg", height=170,
                 placeholder="Paste the offer message or email here...")
    c1, c2 = st.columns(2)
    c1.text_input("Sender's email (optional)", key="sender", placeholder="hr@company.com")
    c2.text_input("Company name (optional)", key="company", placeholder="Company name")
    live = st.checkbox("Run live domain checks (domain age and mail records)", value=True)
    b1, b2 = st.columns([3, 1])
    check_clicked = b1.button("Check offer", type="primary")
    b2.button("Clear", on_click=clear_all)

go = check_clicked or st.session_state.pop("go", False)

# ---------- Run the check ----------
if go:
    message = st.session_state.msg
    if message.strip() == "":
        st.warning("Please paste a message first.")
    else:
        with st.spinner("Reading the message, matching scam patterns, checking the sender..."):
            score, matches = check_message(message, st.session_state.sender,
                                           st.session_state.company, live)
        level = risk_level(score)
        st.session_state.result = {
            "score": score, "matches": matches, "level": level, "message": message,
            "sender": st.session_state.sender, "company": st.session_state.company,
        }
        st.session_state.field = guess_field(message)
        history = [h for h in st.session_state.history if h["msg"] != message]
        st.session_state.history = ([{"msg": message[:1500], "sender": st.session_state.sender,
                                      "company": st.session_state.company,
                                      "level": level, "score": score}] + history)[:5]

# ---------- Show the result ----------
res = st.session_state.result
if res:
    st.markdown(gauge_html(res["score"], res["level"]), unsafe_allow_html=True)

    tab1, tab2, tab3, tab4 = st.tabs(["🔎 Why this score", "✍️ Your message",
                                      "🧭 Cross-check", "🌱 Genuine internships"])

    with tab1:
        if res["matches"]:
            for group in ["Warning signs", "Missing details", "Sender check"]:
                items = [m for m in res["matches"] if m["group"] == group]
                if items:
                    st.markdown(f"**{group}**")
                    st.markdown("".join(finding_html(m) for m in items), unsafe_allow_html=True)
        else:
            st.write("No warning signs matched. That does not prove the offer is genuine.")
        st.download_button("⬇️ Download report",
                           report_text(res["level"], res["score"], res["matches"], res["message"]),
                           file_name="offerguard-report.txt")

    with tab2:
        words = [w for m in res["matches"] if m["group"] == "Warning signs" for w in m["found"]]
        st.markdown(highlight_html(res["message"], words), unsafe_allow_html=True)
        st.caption("Highlighted phrases triggered a warning sign.")

    with tab3:
        domain = link_domain(res["sender"], res["message"])
        groups = crosscheck_links(res["company"], domain)
        if not res["company"].strip() and not domain:
            st.info("Add the company name and the sender's email above to unlock company and website checks.")
        for heading, links in groups:
            st.markdown(f"**{heading}**")
            cols = st.columns(len(links))
            for col, (label, url) in zip(cols, links):
                col.link_button(label, url)

    with tab4:
        st.caption("Trusted places to look instead. Pick a field to update the searches.")
        field = st.radio("Field", list(FIELDS), key="field", horizontal=True,
                         label_visibility="collapsed")
        platforms, official = genuine_links(field)
        st.markdown(f"**Popular platforms ({field})**")
        cols = st.columns(len(platforms))
        for col, (label, url) in zip(cols, platforms):
            col.link_button(label, url)
        st.markdown("**Government and college portals**")
        cols = st.columns(2)
        for i, (label, url) in enumerate(official):
            cols[i % 2].link_button(label, url)
        st.caption("Real listings never ask you to pay to get selected. Apply through the platform "
                   "or the company's own careers page.")

# ---------- Recent checks ----------
if st.session_state.history:
    with st.expander("Recent checks (this session)"):
        for i, h in enumerate(st.session_state.history):
            st.button(f"{h['level']} ({h['score']}) · {h['msg'][:60]}...", key=f"hist{i}",
                      on_click=load_history, args=(i,))

st.caption("OfferGuard shows warning signs, not a verdict. A low score does not prove an offer is genuine.")
