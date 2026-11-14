import html
import random
import re
import time
from datetime import datetime, timezone
from urllib.parse import quote, quote_plus, urlparse

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


# ============================================================
# LIVE LOOKUPS: domain age (RDAP) and mail records (DNS)
# These talk to free public services, so they can fail. The code:
#   - sends a proper User-Agent (some servers reject the default one)
#   - retries once on timeouts, 429 and 5xx errors
#   - has a backup service for each lookup
#   - NEVER remembers a failure (only good answers are cached)
#   - tells you the real reason when a lookup fails
# ============================================================
HTTP_HEADERS = {"User-Agent": "OfferGuard/1.0 (student scam checker)",
                "Accept": "application/json"}
HTTP_TIMEOUT = (3, 5)   # (connect, read) seconds: fail fast instead of freezing the page
CACHE_SECONDS = 3600
HOST_DOWN_SECONDS = 60  # after a service cannot be reached, skip it for this long


@st.cache_resource
def _lookup_cache():
    """One dictionary shared by every visitor. Only successful lookups are stored."""
    return {}


def _cache_get(key, ttl=CACHE_SECONDS):
    entry = _lookup_cache().get(key)
    if entry and time.time() - entry[0] < ttl:
        return entry[1]
    return None


def _cache_put(key, value):
    _lookup_cache()[key] = (time.time(), value)


def _get_json(url, params=None, headers=None):
    """GET a URL. Returns (json, "") on success or (None, short reason) on failure.
    If a service cannot be reached, it is skipped for a minute so the page never freezes."""
    host = urlparse(url).netloc
    if _cache_get("down:" + host, HOST_DOWN_SECONDS):
        return None, "service not reachable"
    reason = "unknown error"
    for attempt in range(2):
        try:
            r = requests.get(url, params=params, timeout=HTTP_TIMEOUT,
                             headers={**HTTP_HEADERS, **(headers or {})})
            if r.status_code == 200:
                return r.json(), ""
            reason = f"HTTP {r.status_code}"
            if r.status_code not in (429, 500, 502, 503, 504):
                break  # retrying will not help (for example 404)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            _cache_put("down:" + host, True)
            reason = "timed out" if isinstance(e, requests.exceptions.Timeout) else "could not connect"
            break  # do not wait again on a service that is not answering
        except ValueError:
            reason = "unreadable reply"
            break
        except Exception as e:
            reason = type(e).__name__
            break
        if attempt == 0:
            time.sleep(0.6)
    return None, reason


def _rdap_urls(domain):
    """First the rdap.org redirector, then (only if needed) the registry's own server."""
    yield "https://rdap.org/domain/" + domain
    tld = domain.rsplit(".", 1)[-1].lower()
    boot, _ = _get_json("https://data.iana.org/rdap/dns.json")
    for names, urls in (boot or {}).get("services", []):
        if tld in names and urls:
            base = urls[0] if urls[0].endswith("/") else urls[0] + "/"
            yield base + "domain/" + domain
            return


def _parse_date(text):
    """Read an RDAP date such as 2019-05-05T07:00:00.000Z."""
    text = re.sub(r"\.\d+", "", str(text)).replace("Z", "+00:00")
    date = datetime.fromisoformat(text)
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return date


def _registrar_name(data):
    try:
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                for item in (entity.get("vcardArray") or [None, []])[1]:
                    if item and item[0] == "fn":
                        return str(item[3])
    except (IndexError, TypeError, AttributeError):
        pass
    return ""


def _profile_from_rdap(data):
    """Turn an RDAP reply into a small dictionary, or None if it has no registration date."""
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])
              if e.get("eventAction") and e.get("eventDate")}
    if "registration" not in events:
        return None
    registered = _parse_date(events["registration"])
    age = (datetime.now(timezone.utc) - registered).days
    if age < 0:
        return None
    expires = ""
    if "expiration" in events:
        try:
            expires = _parse_date(events["expiration"]).strftime("%d %b %Y")
        except ValueError:
            pass
    return {
        "age": age,
        "registered": registered.strftime("%d %b %Y"),
        "expires": expires,
        "registrar": _registrar_name(data),
        "nameservers": [str(n.get("ldhName", "")).lower() for n in data.get("nameservers", [])
                        if n.get("ldhName")][:6],
        "status": [str(s) for s in data.get("status", [])][:6],
    }


def lookup_domain_profile(domain):
    """Returns (profile_dict, reason). profile is None if we could not find out; reason says why."""
    key = "rdap:" + domain
    cached = _cache_get(key)
    if cached is not None:
        return cached, ""
    reason = "no answer"
    for url in _rdap_urls(domain):
        data, err = _get_json(url, headers={"Accept": "application/rdap+json"})
        if data is None:
            reason = err
            continue
        try:
            profile = _profile_from_rdap(data)
        except (ValueError, KeyError, TypeError, AttributeError):
            profile = None
        if profile is not None:
            _cache_put(key, profile)
            return profile, ""
        reason = "the registry reply had no registration date"
    return None, reason


def lookup_domain_age(domain):
    """Returns (age_in_days, reason). age is None if we could not find out."""
    profile, reason = lookup_domain_profile(domain)
    return (profile["age"], "") if profile else (None, reason)


def _dns_records(name, record_type):
    """Ask Google DNS, then Cloudflare DNS. Returns (status, answers, reason).
    status is 0 (found), 3 (domain does not exist) or None (both services failed)."""
    providers = [("https://dns.google/resolve", {}),
                 ("https://cloudflare-dns.com/dns-query", {"Accept": "application/dns-json"})]
    reason = "no answer"
    for url, extra in providers:
        data, err = _get_json(url, params={"name": name, "type": record_type}, headers=extra)
        if data is None:
            reason = err
            continue
        status = data.get("Status")
        if status in (0, 3):
            answers = [str(a.get("data", "")) if isinstance(a, dict) else str(a)
                       for a in (data.get("Answer") or [])]
            return status, answers, ""
        reason = f"DNS error code {status}"
    return None, [], reason


def _dns_query(name, record_type):
    """Returns (status, has_answer, reason)."""
    status, answers, reason = _dns_records(name, record_type)
    return status, bool(answers), reason


def lookup_mail_dns(domain):
    """Returns (state, reason). state is 'ok', 'no_domain', 'no_mail' or 'unknown'."""
    key = "dns:" + domain
    cached = _cache_get(key)
    if cached is not None:
        return cached, ""
    for record_type in ["MX", "A"]:
        status, has_answer, reason = _dns_query(domain, record_type)
        if status is None:
            return "unknown", reason  # a failure: do not cache
        if status == 3:
            _cache_put(key, "no_domain")
            return "no_domain", ""
        if has_answer:
            _cache_put(key, "ok")
            return "ok", ""
    _cache_put(key, "no_mail")
    return "no_mail", ""


def lookup_dns_profile(domain):
    """Mail servers, website address, SPF and DMARC. Returns (profile_dict, reason)."""
    key = "dnsp:" + domain
    cached = _cache_get(key)
    if cached is not None:
        return cached, ""
    status, mx, reason = _dns_records(domain, "MX")
    if status is None:
        return None, reason
    if status == 3:
        profile = {"exists": False, "mx": [], "a": [], "spf": False, "dmarc": False}
        _cache_put(key, profile)
        return profile, ""
    s_a, a_records, _ = _dns_records(domain, "A")
    s_t, txt, _ = _dns_records(domain, "TXT")
    s_d, dmarc_txt, _ = _dns_records("_dmarc." + domain, "TXT")
    profile = {
        "exists": True,
        "mx": sorted({m.split()[-1].rstrip(".").lower() for m in mx if m.split()}),
        "a": [x for x in a_records if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", x)][:4],
        "spf": None if s_t is None else any(t.strip('"').lower().startswith("v=spf1") for t in txt),
        "dmarc": None if s_d is None else any(t.strip('"').lower().startswith("v=dmarc1")
                                              for t in dmarc_txt),
    }
    if None not in (s_a, s_t, s_d):  # only remember a complete answer
        _cache_put(key, profile)
    return profile, ""


def _company_words(name):
    """The meaningful words of a company name (no Pvt, Ltd, and so on)."""
    return [w for w in re.findall(r"[a-z0-9]+", name.lower())
            if len(w) >= 3 and w not in IGNORE_WORDS]


def lookup_company_wiki(company):
    """Look for an encyclopedia page about the company (Wikipedia search).
    Returns (match_dict_or_None, reason). reason is '' when the lookup itself worked."""
    name = company.strip()
    words = _company_words(name)
    if not words:
        return None, "the name is too short to look up"
    key = "wiki:" + name.lower()
    cached = _cache_get(key)
    if cached is not None:  # False means: we looked and found nothing
        return (cached or None), ""
    data, err = _get_json("https://en.wikipedia.org/w/api.php",
                          params={"action": "query", "list": "search", "srsearch": name,
                                  "srlimit": 5, "format": "json"})
    if data is None:
        return None, err
    match = None
    for hit in (data.get("query", {}).get("search", []) or []):
        title = str(hit.get("title", ""))
        squashed = re.sub(r"[^a-z0-9]+", "", title.lower())
        if all(w in squashed for w in words):  # every real word of the name is in the title
            snippet = html.unescape(re.sub(r"<[^>]+>", "", str(hit.get("snippet", ""))))
            match = {"title": title, "snippet": snippet,
                     "url": "https://en.wikipedia.org/wiki/" + quote(title.replace(" ", "_"))}
            break
    _cache_put(key, match or False)
    return match, ""


def check_domain(domain, group="Sender check", label=""):
    """Live checks on the sender's domain. Returns a list of findings."""
    results = []

    dns, dns_reason = lookup_mail_dns(domain)
    if dns == "no_domain":
        results.append({
            "group": group, "name": label + "Domain does not exist", "points": 30,
            "reason": "The sender's domain has no DNS records at all, so it is probably fake.",
            "found": [domain],
        })
    elif dns == "no_mail":
        results.append({
            "group": group, "name": label + "Domain cannot receive email", "points": 15,
            "reason": "The domain exists but has no mail records, which is unusual for a real company.",
            "found": [domain],
        })
    elif dns == "unknown":
        results.append({
            "group": group, "name": "Mail records could not be checked", "points": 0,
            "reason": f"The DNS lookup failed ({dns_reason}). This is a connection problem, "
                      "so it does not count against the offer. Try again in a moment.",
            "found": [domain],
        })

    age, age_reason = lookup_domain_age(root_domain(domain))
    if age is None:
        results.append({
            "group": group, "name": "Domain age could not be checked", "points": 0,
            "reason": f"The lookup failed ({age_reason}). This can be a connection problem or a "
                      "domain ending the registry does not cover, so it does not count against the offer.",
            "found": [domain],
        })
    elif age < 30:
        results.append({
            "group": group, "name": label + f"Domain is only {age} days old", "points": 35,
            "reason": "Scam websites are often created days before they are used. Real companies "
                      "usually have older domains.",
            "found": [domain],
        })
    elif age < 90:
        results.append({
            "group": group, "name": label + f"Domain is only {age} days old", "points": 20,
            "reason": "The domain was registered recently. Check that the company really exists.",
            "found": [domain],
        })
    elif age < 180:
        results.append({
            "group": group, "name": label + f"Domain is {age} days old", "points": 10,
            "reason": "The domain is fairly new. Not a problem by itself, but verify the company.",
            "found": [domain],
        })
    else:
        results.append({
            "group": group, "name": f"Domain is about {age // 365} year(s) old"
            if age >= 365 else f"Domain is {age} days old", "points": 0,
            "reason": "An older domain is a good sign, but scammers can also hijack or buy old domains.",
            "found": [domain],
        })
    return results


# ============================================================
# LINK SCANNING: checks the links found inside the message
# ============================================================
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd",
                  "shorturl.at", "ow.ly", "tiny.cc", "rebrand.ly", "t.ly", "buff.ly"]
SUSPICIOUS_TLDS = (".xyz", ".top", ".click", ".icu", ".buzz", ".cfd", ".sbs", ".monster",
                   ".rest", ".tk", ".gq", ".ml", ".cf")
TRUSTED_LINK_DOMAINS = ["linkedin.com", "internshala.com", "unstop.com", "naukri.com", "google.com",
                        "forms.gle", "zoom.us", "microsoft.com", "github.com", "youtube.com"]
TRUSTED_LINK_SUFFIXES = (".gov.in", ".nic.in", ".ac.in", ".edu")
PAYMENT_WORDS = ["pay", "payment", "upi", "checkout", "deposit", "fee", "fees"]
LINK_POINTS_CAP = 50  # links can add at most this many points in total
URL_PATTERN = (r"(?:https?://|www\.)[^\s<>\"')\]]+|\b(?:"
               + "|".join(re.escape(d) for d in URL_SHORTENERS) + r")/[^\s<>\"')\]]*")


def extract_links(message):
    """Find links in the message. Returns the links as written (max 5, no repeats)."""
    links = []
    for raw in re.findall(URL_PATTERN, message, flags=re.IGNORECASE):
        raw = raw.rstrip(".,;:!?")
        if raw and raw not in links:
            links.append(raw)
    return links[:5]


def link_host(raw):
    """Return (host name, parsed link) for a link, or ("", None) if it cannot be read."""
    try:
        parsed = urlparse(raw if "://" in raw else "http://" + raw)
        return (parsed.hostname or "").lower(), parsed
    except ValueError:
        return "", None


def is_trusted_link(host):
    return root_domain(host) in TRUSTED_LINK_DOMAINS or host.endswith(TRUSTED_LINK_SUFFIXES)


def check_links(message, skip_domain="", live=True):
    """Look at every link in the message. Returns a list of findings (group 'Link check')."""
    results = []
    total = 0
    seen = set()
    live_checked = 0
    skip_root = root_domain(skip_domain) if skip_domain else ""

    def add(host, name, points, reason):
        nonlocal total
        points = min(points, LINK_POINTS_CAP - total)
        if points <= 0:
            return
        total += points
        results.append({"group": "Link check", "name": name, "points": points,
                        "reason": reason, "found": [host]})

    for raw in extract_links(message):
        host, parsed = link_host(raw)
        if not host or "." not in host or host in seen:
            continue
        seen.add(host)
        if is_trusted_link(host):
            continue

        is_short = host in URL_SHORTENERS
        is_ip = re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) is not None

        if is_short:
            add(host, "Shortened link", 20,
                "Shortened links hide where they really go. Scammers use them to disguise payment or form pages.")
        if is_ip:
            add(host, "Link uses a raw IP address", 25,
                "A link that uses numbers instead of a website name is a common sign of a throwaway or fake site.")
        if parsed is not None and parsed.username is not None:
            add(host, "Link hides its real address with @", 25,
                "A link containing an @ sign can hide the real website name before it.")
        if host.endswith(SUSPICIOUS_TLDS):
            add(host, "Unusual domain ending", 10,
                "This ending is often used for cheap throwaway websites. It is not proof of a scam, so check the company.")
        if host.count("-") >= 3:
            add(host, "Address has many hyphens", 10,
                "Many hyphens in a web address often point to a lookalike or throwaway site.")
        if raw.lower().startswith("http://"):
            add(host, "Link is not encrypted (http)", 5,
                "Real companies rarely use unencrypted links for forms or payments.")
        words = re.split(r"[^a-z0-9]+", (host + " " + (parsed.path if parsed else "")).lower())
        if any(w in PAYMENT_WORDS for w in words):
            add(host, "Link looks like a payment page", 15,
                "Real internships never ask you to pay to be selected.")

        # Live check: how old is the linked website, and does it exist?
        if live and live_checked < 3 and not is_short and not is_ip:
            root = root_domain(host)
            if root != skip_root:
                live_checked += 1
                for f in check_domain(root, group="Link check", label="Link: "):
                    if f["points"] > 0:
                        add(host, f["name"], f["points"], f["reason"])
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

    # 5) Links inside the message
    matches += check_links(message, domain or "", live)

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
GROUP_COLORS = {"Warning signs": "#e03e5a", "Missing details": "#f5a524", "Sender check": "#6c4cf1", "Link check": "#0b7285"}
GROUP_CLASS = {"Warning signs": "w", "Missing details": "m", "Sender check": "s", "Link check": "l"}
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
# Three buttons, 10 made-up samples each: fee scams, fake HR emails, genuine offers.
EXAMPLE_POOLS = [
 [
  {
   "m": "Dear Student, you are selected for a 2 month Content Writing internship (work from home, stipend Rs 5000). A registration fee of Rs 500 is required to confirm your seat. Write to hr@writeworks.in for payment details.",
   "s": "",
   "c": ""
  },
  {
   "m": "Congratulations! You are selected for our Data Entry internship. Pay a registration fee of Rs 500 to confirm your seat. Contact us on WhatsApp.",
   "s": "",
   "c": ""
  },
  {
   "m": "Dear Candidate, your application for the Online Survey internship is approved. Pay Rs 299 as processing fee today only and start earning. Stipend Rs 6000, remote, 1 month. Email: join@surveyhub.in. Pay here: http://bit.ly/survey-join-299",
   "s": "",
   "c": ""
  },
  {
   "m": "Part time typing internship, 2 months. Pay a training fee of Rs 800 to begin. Message us on Telegram.",
   "s": "",
   "c": ""
  },
  {
   "m": "Government approved internship! Pay Rs 1200 as security deposit and receive your offer letter. Last chance, seats are filling fast.",
   "s": "",
   "c": ""
  },
  {
   "m": "Final reminder: your internship seat will be cancelled if the registration fee of Rs 350 is not paid immediately. Reply to this number with the screenshot.",
   "s": "",
   "c": ""
  },
  {
   "m": "Shortlisted for Social Media Intern at a reputed firm. No interview required. Pay Rs 999 registration fee to lock your seat. Duration 3 months, stipend Rs 7000, work from home. Contact: jobs@reputedfirm.co",
   "s": "",
   "c": ""
  },
  {
   "m": "Congratulations, you are directly selected for a 100% placement guaranteed course plus internship. Pay the processing fee of Rs 4999. Share your PAN card on Telegram.",
   "s": "",
   "c": ""
  },
  {
   "m": "Work from home product review job for students. Immediately pay the kit fee of Rs 700 to get your login ID. Duration 1 month. Login: http://203.0.113.45/portal",
   "s": "",
   "c": ""
  },
  {
   "m": "Dear Candidate, a refundable security deposit of Rs 2000 is needed before we issue your joining letter for the 3 month Python internship (stipend Rs 8000, hybrid). Pay via the link: https://pay.joinletter.xyz/secure",
   "s": "",
   "c": ""
  }
 ],
 [
  {
   "m": "Dear Candidate, we are pleased to offer you a 3 month Marketing internship at Lumora Analytics, starting 1 December. Stipend: Rs 12000 per month, hybrid. Please reply from this email only and keep the offer confidential.",
   "s": "hr.lumoraanalytics@gmail.com",
   "c": "Lumora Analytics"
  },
  {
   "m": "Hello, your profile fits a 4 month Data Analyst internship at Vertexa Labs, remote, stipend Rs 20000 per month. Confirm immediately as only a few seats are left. Confirm here: tinyurl.com/vertexa-confirm",
   "s": "vertexa.recruitment@yahoo.in",
   "c": "Vertexa Labs"
  },
  {
   "m": "Hi, HR here from Novaspark Media. We offer a 2 month Video Editing internship, office based, stipend Rs 9000. Continue the process on WhatsApp to receive your joining kit.",
   "s": "novaspark.hr@hotmail.com",
   "c": "Novaspark Media"
  },
  {
   "m": "Greetings from Quantleaf Systems. We are offering a 6 month Software Engineer trainee role, Rs 25000 per month, office based. To generate your employee ID, please share a scan of your Aadhaar by email.",
   "s": "quantleaf.careers@outlook.com",
   "c": "Quantleaf Systems"
  },
  {
   "m": "Dear Candidate, your resume fits our 3 month Business Analyst internship at Brightwave Consulting. Stipend Rs 15000 per month, work from home. A refundable security deposit of Rs 2000 is needed before the first session.",
   "s": "brightwave.hiring@gmail.com",
   "c": "Brightwave Consulting"
  },
  {
   "m": "Dear Student, congratulations! You are selected for a 2 month Graphic Design internship at PixelNest Studio, stipend Rs 8000, work from home. No interview needed. Please confirm within 24 hours.",
   "s": "pixelnest.hr@outlook.com",
   "c": "PixelNest Studio"
  },
  {
   "m": "Hello, Vertexa Labs is hiring a 3 month Web Developer intern, remote, stipend Rs 20000 per month. Pay a processing fee of Rs 750 immediately to activate your company email.",
   "s": "vertexa.hr@yahoo.in",
   "c": "Vertexa Labs"
  },
  {
   "m": "Dear Applicant, Kairo Fintech is hiring a Finance intern for 2 months, Rs 12000 stipend, remote. Please send your bank account details on Telegram to activate your payroll account.",
   "s": "kairo.fintech.hr@rediffmail.com",
   "c": "Kairo Fintech"
  },
  {
   "m": "Dear Applicant, we offer a 1 month Marketing internship at Mintora Foods, stipend Rs 7000, office based. A security deposit of Rs 1500 is needed for your uniform and ID card. Kindly pay and share your password to access the training portal.",
   "s": "mintora.foods.hr@yahoo.com",
   "c": "Mintora Foods"
  },
  {
   "m": "Dear Candidate, we offer you a 3 month Operations internship at Skyforge Logistics, office based, stipend Rs 14000. Kindly pay a registration fee of Rs 600 to confirm your seat.",
   "s": "careers@jobs-hiring-portal.net",
   "c": "Skyforge Logistics"
  }
 ],
 [
  {
   "m": "Dear Ishaan, thank you for attending the interview on Friday. We are glad to offer you a 2 month Robotics Engineering internship at Greenfield Robotics, starting 10 January. The stipend is Rs 15000 per month and the work is on site at our Pune office. Please reply to confirm your acceptance. Contact: talent@greenfieldrobotics.in",
   "s": "talent@greenfieldrobotics.in",
   "c": "Greenfield Robotics"
  },
  {
   "m": "Hello Sneha, congratulations on clearing both interview rounds. Sunrise Learning would like to offer you a 3 month UX Design internship, starting 15 December. This is a remote role with a stipend of Rs 10000 per month. The offer letter and joining instructions are attached to this email. Write to interns@sunriselearning.com with any questions.",
   "s": "interns@sunriselearning.com",
   "c": "Sunrise Learning"
  },
  {
   "m": "Dear Rohan, we are pleased to offer you a 6 month Operations internship at UrbanLoop Mobility, hybrid, with a monthly stipend of Rs 14000. Your reporting manager will be Kavita Nair. A WhatsApp group will be created for day to day coordination. Please sign and return the offer letter by 20 November. More details at https://urbanloop.in/careers",
   "s": "careers@urbanloop.in",
   "c": "UrbanLoop Mobility"
  },
  {
   "m": "Hi Tanya, Maple Design Studio is happy to invite you for an 8 week Graphic Design internship, office based in Gurugram. Please send your portfolio link to jobs@mapledesign.in before your start date of 3 February. We look forward to working with you.",
   "s": "jobs@mapledesign.in",
   "c": "Maple Design Studio"
  },
  {
   "m": "Dear Kabir, following your interview with the engineering team, Orchid Software is pleased to offer you a 4 month Software Developer internship. The stipend is Rs 22000 per month and the work location is our Noida office. Kindly confirm your acceptance by email. Regards, Meenal Rao, careers@orchidsoftware.com",
   "s": "careers@orchidsoftware.com",
   "c": "Orchid Software"
  },
  {
   "m": "Dear Ananya, Riverbend Foundation invites you to join as a Research intern for 10 weeks, unpaid but with a certificate and travel allowance, in a remote role. Please read the attached guidelines and reply to volunteers@riverbend.org by 25 November.",
   "s": "volunteers@riverbend.org",
   "c": "Riverbend Foundation"
  },
  {
   "m": "Hi Dev, thanks for your time during the interview. Coral Cloud Services is delighted to offer you a 3 month Cloud Support internship, remote, stipend Rs 16000 per month, starting 2 February. Your onboarding guide is at https://coralcloud.io/welcome. For questions, write to hr@coralcloud.io.",
   "s": "hr@coralcloud.io",
   "c": "Coral Cloud Services"
  },
  {
   "m": "Hi Neel, welcome aboard! Harbor Retail is offering you a 6 week Sales internship, office based, with a stipend of Rs 7000. Join our Telegram channel for team updates. Write to people@harborretail.in if you have questions.",
   "s": "people@harborretail.in",
   "c": "Harbor Retail"
  },
  {
   "m": "Dear Pooja, Redwood Health is offering you a Research Assistant internship starting 1 February, hybrid, with a stipend of Rs 9000 per month. Please reply to this email to accept. Contact: hr@redwoodhealth.in",
   "s": "hr@redwoodhealth.in",
   "c": "Redwood Health"
  },
  {
   "m": "Dear Karan, we are delighted to offer you a 3 month Finance internship at Quill and Co Advisors, remote. Please confirm your acceptance by replying to finance@quillco.in",
   "s": "finance@quillco.in",
   "c": "Quill and Co Advisors"
  }
 ]
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
.og-chip {display: inline-block; padding: 3px 11px; border-radius: 999px; font-size: .82rem; font-weight: 700; margin: 2px 6px 2px 0;}
.og-chip.ok {background: #1fa97122; color: #13805a;}
.og-chip.warn {background: #f5a52433; color: #a86300;}
.og-chip.bad {background: #e03e5a22; color: #b3213b;}
.og-chip.info {background: #6c4cf122; color: #4b32c4;}
.og-kv {width: 100%; border-collapse: collapse; font-size: .93rem; margin-top: 6px;}
.og-kv td {padding: 5px 6px; vertical-align: top; border-bottom: 1px solid rgba(128,128,128,.18); word-break: break-word;}
.og-kv td:first-child {opacity: .7; width: 34%;}
.og-verdict {margin: 10px 0 0; font-weight: 700; font-size: .93rem;}
.og-verdict.ok {color: #13805a;} .og-verdict.warn {color: #a86300;}
.og-verdict.bad {color: #b3213b;} .og-verdict.info {color: #4b32c4;}
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
    if re.search(r"data analy|data scien|analyst", t):
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


ACTIONS = {
    "High": ("🛑", "Stop. Do not reply or pay yet.", [
        "Do not pay any fee or deposit, even if it is called refundable.",
        "Do not share Aadhaar, PAN, bank details, passwords or OTPs.",
        "Do not click links or continue the chat until you have checked the company.",
        "Check the company on its official website and LinkedIn page (see the Cross-check tab).",
        "If you already paid or shared documents: call 1930 or report at cybercrime.gov.in, and inform your bank.",
    ]),
    "Medium": ("⚠️", "Pause before you reply.", [
        "Check the company on its official website and LinkedIn page (see the Cross-check tab).",
        "Confirm that the recruiter's email domain matches the company's website.",
        "Ask for a written offer that clearly states the role, duration and pay.",
        "Do not pay money or send ID documents until the company is verified.",
        "Ask your college placement cell or a senior if you are unsure.",
    ]),
    "Low": ("✅", "Few warning signs, but still confirm.", [
        "A low score does not prove an offer is genuine.",
        "Confirm the company's website and that the recruiter's email domain matches it.",
        "Real offers never ask you to pay to get selected.",
        "Share ID documents only after you have verified the company and accepted a written offer.",
    ]),
}


def action_html(level):
    """The 'What to do now' card shown under the gauge."""
    icon, title, steps = ACTIONS[level]
    color = LEVEL_COLORS[level]
    items = "".join(f"<li>{html.escape(step)}</li>" for step in steps)
    return (
        f'<div class="og-card" style="border-left:6px solid {color}">'
        f'<div style="font-weight:800;font-size:1.05rem">{icon} What to do now: {html.escape(title)}</div>'
        f'<ol style="margin:8px 0 0 1.1rem;padding:0;line-height:1.55">{items}</ol></div>'
    )


def report_text(level, score, matches, message):
    lines = ["OFFERGUARD REPORT", f"Risk: {level} ({score}/100)", ""]
    for m in matches:
        lines.append(f"- {m['name']} (+{m['points']}): {m['reason']}")
    lines += ["", "Message checked:", message, "",
              "This shows warning signs, not a verdict. Cross-check the company before trusting an offer."]
    return "\n".join(lines)


def _pdf_safe(text):
    """The PDF's built-in fonts only know Western characters. Returns (safe_text, changed)."""
    safe = text.encode("cp1252", "replace").decode("cp1252")
    return safe, safe != text


def _tint(hex_color, amount=0.88):
    """Blend a colour with white (amount=1 would be pure white). Used for soft backgrounds."""
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    mix = lambda c: round(c + (255 - c) * amount)
    return "#%02x%02x%02x" % (mix(r), mix(g), mix(b))


def report_pdf(level, score, matches, message, sender="", company=""):
    """Build the PDF report and return it as bytes.
    (reportlab is imported here so the rest of the app still works if it is missing.)"""
    from io import BytesIO
    from xml.sax.saxutils import escape
    from reportlab.graphics.shapes import Drawing, Rect
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    PURPLE = colors.HexColor("#6c4cf1")
    INK = colors.HexColor("#2b2540")
    MUTED = colors.HexColor("#6b6585")
    level_hex = LEVEL_COLORS[level]
    level_col = colors.HexColor(level_hex)
    WIDTH = 174 * mm  # usable page width
    changed = [False]  # becomes True if some characters could not be shown

    def esc(text):
        safe, was_changed = _pdf_safe(str(text))
        changed[0] = changed[0] or was_changed
        return escape(safe)

    def style(name, **kw):
        base = dict(fontName="Helvetica", fontSize=10, leading=14, textColor=INK)
        base.update(kw)
        return ParagraphStyle(name, **base)

    body = style("body")
    small = style("small", fontSize=8.5, leading=12, textColor=MUTED)
    reason_style = style("reason", fontSize=9, leading=12.5)
    right = style("right", fontName="Helvetica-Bold", alignment=TA_RIGHT)
    heading = style("heading", fontName="Helvetica-Bold", fontSize=13, leading=17,
                    spaceBefore=16, spaceAfter=6, textColor=PURPLE)
    message_style = style("message", fontSize=9.5, leading=13.5, wordWrap="CJK")

    def card(rows, color_hex, widths, spans=()):
        """A soft coloured box with a thick coloured bar on its left side."""
        t = Table(rows, colWidths=widths)
        cmds = [("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(_tint(color_hex, 0.9))),
                ("LINEBEFORE", (0, 0), (0, -1), 4, colors.HexColor(color_hex)),
                ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "TOP")]
        cmds += [("SPAN", (0, r), (-1, r)) for r in spans]
        t.setStyle(TableStyle(cmds))
        return t

    # ---------- Page decoration: purple header band, shield logo, footer ----------
    stamp = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")

    def draw_page(canvas, doc):
        w, h = A4
        canvas.saveState()
        canvas.setFillColor(PURPLE)
        canvas.rect(0, h - 24 * mm, w, 24 * mm, stroke=0, fill=1)
        x, y = 18 * mm, h - 19 * mm  # shield logo
        p = canvas.beginPath()
        p.moveTo(x, y + 11 * mm)
        p.lineTo(x + 4.5 * mm, y + 13 * mm)
        p.lineTo(x + 9 * mm, y + 11 * mm)
        p.lineTo(x + 9 * mm, y + 6 * mm)
        p.curveTo(x + 9 * mm, y + 2.5 * mm, x + 6.5 * mm, y + 1 * mm, x + 4.5 * mm, y)
        p.curveTo(x + 2.5 * mm, y + 1 * mm, x, y + 2.5 * mm, x, y + 6 * mm)
        p.close()
        canvas.setFillColor(colors.white)
        canvas.drawPath(p, stroke=0, fill=1)
        canvas.setStrokeColor(PURPLE)
        canvas.setLineWidth(1.6)
        canvas.lines([(x + 2.3 * mm, y + 6.3 * mm, x + 4 * mm, y + 4.5 * mm),
                      (x + 4 * mm, y + 4.5 * mm, x + 6.9 * mm, y + 8.3 * mm)])
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 20)
        canvas.drawString(31 * mm, h - 14 * mm, "OfferGuard")
        canvas.setFillColor(colors.HexColor("#ddd5ff"))
        canvas.setFont("Helvetica", 9)
        canvas.drawString(31 * mm, h - 19.5 * mm, "Internship and job offer risk report")
        canvas.drawRightString(w - 18 * mm, h - 14 * mm, "Generated " + stamp)
        canvas.setStrokeColor(colors.HexColor("#d9d3ee"))
        canvas.setLineWidth(0.6)
        canvas.line(18 * mm, 15 * mm, w - 18 * mm, 15 * mm)
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(18 * mm, 10.5 * mm,
                          "OfferGuard shows warning signs, not a verdict. Always cross-check the company.")
        canvas.drawRightString(w - 18 * mm, 10.5 * mm, f"Page {doc.page}")
        canvas.restoreState()

    story = []

    # ---------- 1. Score summary ----------
    score_cell = [Paragraph(f'<font size="38" color="{level_hex}"><b>{score}</b></font>'
                            f'<font size="14" color="#6b6585"> / 100</font>',
                            style("score", leading=44)),
                  Paragraph("RISK SCORE", small)]
    verdict_cell = [Paragraph(f'<font color="{level_hex}"><b>{level.upper()} RISK</b></font>',
                              style("level", fontSize=19, leading=24)),
                    Spacer(1, 3),
                    Paragraph(esc(SUMMARY[level].replace("Use the cross-check links to confirm the company.",
                                                         "Confirm the company before trusting it.")), body)]
    hero = Table([[score_cell, verdict_cell]], colWidths=[55 * mm, WIDTH - 55 * mm])
    hero.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(_tint(level_hex, 0.88))),
        ("LINEBEFORE", (0, 0), (0, -1), 6, level_col),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 16), ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 14), ("BOTTOMPADDING", (0, 0), (-1, -1), 14)]))
    story.append(hero)
    story.append(Spacer(1, 8))
    bar = Drawing(WIDTH, 7)
    bar.add(Rect(0, 0, WIDTH, 7, fillColor=colors.HexColor("#e6e1f5"), strokeColor=None))
    bar.add(Rect(0, 0, WIDTH * score / 100, 7, fillColor=level_col, strokeColor=None))
    story.append(bar)
    story.append(Spacer(1, 3))
    story.append(Paragraph("Low: 0 to 19  |  Medium: 20 to 49  |  High: 50 to 100", small))

    # ---------- 2. What was checked ----------
    details = []
    if company.strip():
        details.append(f"<b>Company:</b> {esc(company.strip())}")
    if sender.strip():
        details.append(f"<b>Sender email:</b> {esc(sender.strip())}")
    if details:
        story.append(Spacer(1, 8))
        story.append(Paragraph("&nbsp;&nbsp;&nbsp;&nbsp;".join(details), body))

    # ---------- 3. What to do now ----------
    _, action_title, steps = ACTIONS[level]
    story.append(Paragraph("What to do now", heading))
    action_rows = [[Paragraph(f"<b>{esc(action_title)}</b>", body)]]
    action_rows += [[Paragraph(esc(step.replace(" (see the Cross-check tab)", "")),
                               reason_style, bulletText=f"{i}.")]
                    for i, step in enumerate(steps, 1)]
    story.append(card(action_rows, level_hex, [WIDTH]))

    # ---------- 4. Why this score ----------
    story.append(Paragraph("Why this score", heading))
    if not matches:
        story.append(Paragraph("No warning signs matched. That does not prove the offer is genuine.", body))
    for group in ["Warning signs", "Missing details", "Sender check", "Link check"]:
        items = [m for m in matches if m["group"] == group]
        if not items:
            continue
        gcolor = GROUP_COLORS[group]
        total = sum(m["points"] for m in items)
        story.append(Paragraph(
            f'<font color="{gcolor}"><b>{group}</b></font>'
            f'<font color="#6b6585" size="9">  ({len(items)} found, +{total} points)</font>',
            style("group", fontSize=11, leading=15, spaceBefore=6, spaceAfter=4)))
        for m in items:
            rows = [[Paragraph(f"<b>{esc(m['name'])}</b>", body),
                     Paragraph(f"+{m['points']}", right)],
                    [Paragraph(esc(m["reason"]), reason_style), ""]]
            spans = [1]
            if m["found"]:
                rows.append([Paragraph("Found: " + esc(", ".join(m["found"])), small), ""])
                spans.append(2)
            story.append(KeepTogether([card(rows, gcolor, [WIDTH - 22 * mm, 22 * mm], spans),
                                       Spacer(1, 5)]))

    # ---------- 5. The message, with triggered phrases highlighted ----------
    story.append(Paragraph("Message checked", heading))
    shown = re.sub(r"\n[ \t]*\n(?:[ \t]*\n)+", "\n\n", message.strip())
    cut = len(shown) > 3500
    shown = _pdf_safe(shown[:3500])[0]
    changed[0] = changed[0] or _pdf_safe(re.sub(r"\n[ \t]*\n(?:[ \t]*\n)+", "\n\n",
                                               message.strip())[:3500])[1]
    words = [_pdf_safe(w)[0] for m in matches if m["group"] in ("Warning signs", "Link check")
             for w in m["found"]]
    spans_found = []
    for w in sorted(set(words), key=len, reverse=True):
        for hit in re.finditer(r"\b" + re.escape(w) + r"\b", shown, flags=re.IGNORECASE):
            spans_found.append((hit.start(), hit.end()))
    spans_found.sort()
    merged = []
    for s, e in spans_found:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    parts, pos = [], 0
    for s, e in merged:
        parts.append(escape(shown[pos:s]))
        parts.append('<font backColor="#ffe58a">' + escape(shown[s:e]) + "</font>")
        pos = e
    parts.append(escape(shown[pos:]))
    lines = "".join(parts).split("\n")  # a highlight never spans two lines
    msg_box = Table([[Paragraph(line or "&nbsp;", message_style)] for line in lines],
                    colWidths=[WIDTH], splitByRow=1)
    msg_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f7f5fc")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#d9d3ee")),
        ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, 0), 10), ("BOTTOMPADDING", (0, -1), (-1, -1), 10)]))
    story.append(msg_box)
    notes = ["Highlighted phrases triggered a warning sign."] if merged else []
    if cut:
        notes.append("The message was shortened for this report.")
    if changed[0]:
        notes.append("Emoji and non-English letters cannot be shown in this PDF and appear as ?.")
    if notes:
        story.append(Spacer(1, 3))
        story.append(Paragraph(" ".join(notes), small))

    # ---------- 6. Where to verify ----------
    verify = [
        "Search the company on its official website and LinkedIn page.",
        "Make sure the recruiter's email domain matches the company's website.",
        "Look for scam reports: search the company name with the words internship scam.",
        "Already paid or shared documents? Call 1930 or report at cybercrime.gov.in.",
        "Look for genuine internships at pminternship.mca.gov.in, internship.aicte-india.org "
        "or ncs.gov.in.",
    ]
    story.append(KeepTogether([Paragraph("Where to verify", heading)]
                              + [Paragraph(esc(v), reason_style, bulletText="\u2022") for v in verify]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "<b>Important:</b> this report lists warning signs found by an automatic check. "
        "It is not a verdict. A low score does not prove an offer is genuine, and a high "
        "score does not prove it is fake. Always confirm with the company directly.", small))

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=32 * mm, bottomMargin=22 * mm,
                            title="OfferGuard report", author="OfferGuard")
    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    return buf.getvalue()


def chip_html(text, kind="info"):
    """A small coloured pill. kind is ok, warn, bad or info."""
    return f'<span class="og-chip {kind}">{html.escape(text)}</span>'


def domain_card_html(domain, prof, prof_err, dns, dns_err, compact=False):
    """One card with everything we learned about a domain. All text is escaped."""
    chips = []
    rows = []
    if prof:
        age = prof["age"]
        kind = "bad" if age < 90 else "warn" if age < 365 else "ok"
        pretty = f"{age} days" if age < 365 else f"about {age // 365} year(s)"
        chips.append(chip_html(f"Registered {pretty} ago", kind))
        rows += [("Registered on", prof["registered"]), ("Registrar", prof["registrar"])]
        if not compact:
            rows += [("Expires on", prof["expires"]),
                     ("Name servers", ", ".join(prof["nameservers"])),
                     ("Registry status", ", ".join(prof["status"]))]
    else:
        chips.append(chip_html("Registration details unavailable", "info"))
        rows.append(("Registration details", f"Could not be fetched ({prof_err})"))

    if dns:
        if not dns["exists"]:
            chips.append(chip_html("Domain does not exist", "bad"))
        else:
            chips.append(chip_html("Can receive email" if dns["mx"] else "No mail servers",
                                   "ok" if dns["mx"] else "warn"))
            if dns["spf"] is not None:
                chips.append(chip_html("SPF set" if dns["spf"] else "No SPF", "ok" if dns["spf"] else "warn"))
            if dns["dmarc"] is not None:
                chips.append(chip_html("DMARC set" if dns["dmarc"] else "No DMARC",
                                       "ok" if dns["dmarc"] else "warn"))
            if not compact:
                rows += [("Mail servers", ", ".join(dns["mx"][:4])),
                         ("Website address (IP)", ", ".join(dns["a"] or []))]
    else:
        chips.append(chip_html("DNS details unavailable", "info"))
        rows.append(("DNS records", f"Could not be fetched ({dns_err})"))

    if dns and not dns["exists"]:
        verdict = ("This domain does not exist. Treat the offer as fake.", "bad")
    elif prof and prof["age"] < 90:
        verdict = ("A very new domain. Scam sites are often this young.", "bad")
    elif (prof and prof["age"] < 365) or (dns and dns["exists"] and not dns["mx"]):
        verdict = ("A fairly new or incomplete setup. Verify the company before trusting it.", "warn")
    elif prof and dns and dns["mx"]:
        verdict = ("An established domain with working email. A good sign, but not proof.", "ok")
    else:
        verdict = ("Not enough information to judge this domain.", "info")

    table = "".join(f"<tr><td>{html.escape(k)}</td><td>{html.escape(str(v))}</td></tr>"
                    for k, v in rows if v)
    return (f'<div class="og-card"><div style="font-weight:800;font-size:1.02rem;word-break:break-all">'
            f'{html.escape(domain)}</div><div style="margin:6px 0 2px">{"".join(chips)}</div>'
            f'<table class="og-kv">{table}</table>'
            f'<p class="og-verdict {verdict[1]}">{html.escape(verdict[0])}</p></div>')


# ============================================================
# PART 3B: THE WEBSITE (two pages)
#   Page 1 "Check an offer": paste a message, get the score and the reasons.
#   Page 2 "Cross-check": verify the company, sender and links inside OfferGuard.
# ============================================================
st.set_page_config(page_title="OfferGuard", page_icon="🛡️", layout="centered")
st.markdown(CSS, unsafe_allow_html=True)

# Streamlit forgets a box's value when the box is not drawn on the current page.
# So each input has a plain copy (always kept) and a "w_" copy used by the widget.
STATE_KEYS = ["msg", "sender", "company", "live"]

for key, default in [("msg", ""), ("sender", ""), ("company", ""), ("live", True),
                     ("result", None), ("history", []), ("field", "Any"), ("page", "check")]:
    if key not in st.session_state:
        st.session_state[key] = default

if "example_idx" not in st.session_state:
    st.session_state.example_idx = [random.randrange(len(p)) for p in EXAMPLE_POOLS]


def sync():
    """Copy what the visitor typed into the plain copies."""
    for k in STATE_KEYS:
        if "w_" + k in st.session_state:
            st.session_state[k] = st.session_state["w_" + k]


def goto(page):
    sync()
    st.session_state.page = page


def set_inputs(msg, sender, company):
    for k, v in (("msg", msg), ("sender", sender), ("company", company)):
        st.session_state[k] = v
        st.session_state["w_" + k] = v


def load_example(i):
    """Each click on a button loads the NEXT sample from that button's list."""
    pool = EXAMPLE_POOLS[i]
    n = st.session_state.example_idx[i] % len(pool)
    st.session_state.example_idx[i] = (n + 1) % len(pool)
    ex = pool[n]
    set_inputs(ex["m"], ex["s"], ex["c"])
    st.session_state.go = True


def load_history(i):
    item = st.session_state.history[i]
    set_inputs(item["msg"], item["sender"], item["company"])
    st.session_state.go = True


def clear_all():
    set_inputs("", "", "")
    st.session_state.result = None


def enable_live():
    st.session_state.live = True


# ============================================================
# PAGE 1: CHECK AN OFFER
# ============================================================
def page_check():
    for k in STATE_KEYS:
        if "w_" + k not in st.session_state:
            st.session_state["w_" + k] = st.session_state[k]

    st.caption("Try an example")
    ex1, ex2, ex3 = st.columns(3)
    ex1.button("🚩 Fee scam", on_click=load_example, args=(0,))
    ex2.button("🕵️ Fake HR email", on_click=load_example, args=(1,))
    ex3.button("✅ Genuine offer", on_click=load_example, args=(2,))

    with st.container(border=True):
        st.text_area("Offer message", key="w_msg", height=170,
                     placeholder="Paste the offer message or email here...")
        c1, c2 = st.columns(2)
        c1.text_input("Sender's email (optional)", key="w_sender", placeholder="hr@company.com")
        c2.text_input("Company name (optional)", key="w_company", placeholder="Company name")
        st.checkbox("Run live domain checks (domain age and mail records)", key="w_live")
        st.caption("🔒 Privacy: OfferGuard does not save your message in any database, and recent checks "
                   "last only for this session. With live checks on, only domain names (the sender's and "
                   "any in links) and the company name are looked up, never your message or the full "
                   "links. Avoid pasting your own Aadhaar, PAN or bank details.")
        b1, b2 = st.columns([3, 1])
        check_clicked = b1.button("Check offer", type="primary")
        b2.button("Clear", on_click=clear_all)
    sync()

    run = check_clicked or st.session_state.pop("go", False)

    if run:
        message = st.session_state.msg
        if message.strip() == "":
            st.warning("Please paste a message first.")
        else:
            with st.spinner("Reading the message, matching scam patterns, checking the sender..."):
                score, matches = check_message(message, st.session_state.sender,
                                               st.session_state.company, st.session_state.live)
            level = risk_level(score)
            st.session_state.result = {
                "score": score, "matches": matches, "level": level, "message": message,
                "sender": st.session_state.sender, "company": st.session_state.company,
            }
            st.session_state.field = guess_field(message)
            history = [h for h in st.session_state.history if h["msg"] != message[:1500]]
            st.session_state.history = ([{"msg": message[:1500], "sender": st.session_state.sender,
                                          "company": st.session_state.company,
                                          "level": level, "score": score}] + history)[:5]

    res = st.session_state.result
    if res:
        st.markdown(gauge_html(res["score"], res["level"]), unsafe_allow_html=True)
        st.markdown(action_html(res["level"]), unsafe_allow_html=True)

        tab1, tab2 = st.tabs(["🔎 Why this score", "✍️ Your message"])

        with tab1:
            if res["matches"]:
                for group in ["Warning signs", "Missing details", "Sender check", "Link check"]:
                    items = [m for m in res["matches"] if m["group"] == group]
                    if items:
                        st.markdown(f"**{group}**")
                        st.markdown("".join(finding_html(m) for m in items), unsafe_allow_html=True)
            else:
                st.write("No warning signs matched. That does not prove the offer is genuine.")
            try:
                pdf_bytes = report_pdf(res["level"], res["score"], res["matches"], res["message"],
                                       res["sender"], res["company"])
            except Exception:
                pdf_bytes = None
            if pdf_bytes:
                st.download_button("⬇️ Download PDF report", pdf_bytes,
                                   file_name="offerguard-report.pdf", mime="application/pdf")
            else:
                st.download_button("⬇️ Download report (text)",
                                   report_text(res["level"], res["score"], res["matches"], res["message"]),
                                   file_name="offerguard-report.txt")
                st.caption("The PDF could not be made. Check that 'reportlab' is installed "
                           "(it is listed in requirements.txt) and restart the app.")

        with tab2:
            words = [w for m in res["matches"] if m["group"] in ("Warning signs", "Link check")
                     for w in m["found"]]
            st.markdown(highlight_html(res["message"], words), unsafe_allow_html=True)
            st.caption("Highlighted phrases triggered a warning sign.")

        st.button("🧭 Continue to Cross-check  →", on_click=goto, args=("cross",),
                  key="to_cross", type="primary")

    if st.session_state.history:
        with st.expander("Recent checks (this session)"):
            for i, h in enumerate(st.session_state.history):
                st.button(f"{h['level']} ({h['score']}) · {h['msg'][:60]}...", key=f"hist{i}",
                          on_click=load_history, args=(i,))


# ============================================================
# PAGE 2: CROSS-CHECK (everything is shown here, nothing sends you to a search page)
# ============================================================
def page_cross():
    res = st.session_state.result
    st.markdown('<p class="og-title" style="font-size:2rem">🧭 Cross-<span>check</span></p>'
                '<p class="og-sub">Verify the company, the sender and the links without leaving '
                'OfferGuard.</p>', unsafe_allow_html=True)
    if not res:
        st.info("Check an offer on page 1 first. Then come back here to verify the company, "
                "the sender and the links.")
        st.button("←  Go to Check an offer", on_click=goto, args=("check",), key="back_empty")
        return

    if "w_company" not in st.session_state:
        st.session_state.w_company = st.session_state.company
    level, score = res["level"], res["score"]
    color = LEVEL_COLORS[level]
    # The sender's domain comes from an email address only (the box, or the first email in
    # the message). Links are checked separately below.
    domain = get_domain(res["sender"]) if res["sender"].strip() else None
    if not domain:
        emails = re.findall(EMAIL_PATTERN, res["message"].lower())
        domain = get_domain(emails[0]) if emails else None
    is_free = bool(domain) and domain in FREE_EMAIL_DOMAINS
    live = st.session_state.live

    st.markdown(
        f'<div class="og-card" style="border-left:6px solid {color}">'
        f'<span class="og-badge" style="background:{color}22;color:{color};font-size:1rem">'
        f'{html.escape(level)} risk · {score}/100</span>'
        f'<div style="opacity:.8;margin-top:8px">{html.escape(SUMMARY[level])}</div></div>',
        unsafe_allow_html=True)

    if not live:
        st.info("Live lookups are turned off, so domain and company details are not shown.")
        st.button("Turn on live lookups", on_click=enable_live, key="enable_live")

    def domain_block(host, compact=False):
        if live:
            with st.spinner(f"Looking up {host}..."):
                prof, perr = lookup_domain_profile(root_domain(host))
                dns, derr = lookup_dns_profile(host)
        else:
            prof, perr, dns, derr = None, "live lookups are off", None, "live lookups are off"
        st.markdown(domain_card_html(host, prof, perr, dns, derr, compact), unsafe_allow_html=True)

    t_company, t_sender, t_help, t_genuine = st.tabs(
        ["🏢 Company", "🌐 Sender and links", "🚨 Report and get help", "🌱 Genuine internships"])

    # ---------- Company ----------
    with t_company:
        st.text_input("Company name", key="w_company", placeholder="Company name from the offer")
        company = st.session_state.w_company.strip()
        st.session_state.company = company
        if not company:
            st.info("Type the company name above to run the company checks.")
        else:
            words = _company_words(company)
            if is_free:
                st.warning(f"The sender uses a free email service ({domain}). A real company normally "
                           "emails from its own website's domain.")
            elif domain and words:
                domain_text = domain.replace("-", "").replace(".", "")
                if any(w in domain_text for w in words):
                    st.success(f"The domain **{domain}** matches the company name.")
                else:
                    st.warning(f"The domain **{domain}** does not clearly match the company name. "
                               "Check the company's real website for its official email domain.")
            else:
                st.info("There is no sender email to compare with the company name.")

            if live:
                with st.spinner("Looking for public information about the company..."):
                    match, err = lookup_company_wiki(company)
                st.markdown("**Public information**")
                if match:
                    st.markdown(f'<div class="og-card"><b>{html.escape(match["title"])}</b>'
                                f'<div style="margin-top:4px">{html.escape(match["snippet"])}…</div></div>',
                                unsafe_allow_html=True)
                    st.link_button("Read the full encyclopedia page", match["url"])
                    st.caption("A public page means the name belongs to a known organisation. It does "
                               "not prove that this particular offer really came from it.")
                elif err:
                    st.info(f"The encyclopedia could not be reached right now ({err}).")
                else:
                    st.info("No encyclopedia page was found for this name. Small and new companies often "
                            "have none, so this alone says nothing good or bad.")

        st.markdown("**How to confirm a company is real**")
        st.markdown(
            "1. **Registration:** a registered Indian company has a 21-character CIN. Search its name "
            "on the MCA portal and make sure the name matches the offer.\n"
            "2. **Website:** the company should have its own website, and the recruiter's email domain "
            "should be the same as the website's domain.\n"
            "3. **LinkedIn:** the company page should have real employees, real posts and a history, "
            "not just a handful of new accounts.\n"
            "4. **Call back:** phone the number on the company's own website, not the one in the message.\n"
            "5. **In writing:** ask for an offer letter that states the role, duration and pay.")
        st.link_button("Open the MCA portal (official site)", "https://www.mca.gov.in")
        with st.expander("Want to search further? These open in a new tab"):
            for heading, links in crosscheck_links(company, domain if domain and not is_free else None):
                st.markdown(f"**{heading}**")
                cols = st.columns(len(links))
                for col, (label, url) in zip(cols, links):
                    col.link_button(label, url)

    # ---------- Sender and links ----------
    with t_sender:
        st.markdown("**Sender's domain**")
        if not domain:
            st.info("There is no sender email, so there is no sender domain to look up. Add the "
                    "sender's email on page 1 and check again. Links are checked below.")
        elif is_free:
            st.warning(f"**{domain}** is a free email service. Anyone can create an address on it, so "
                       "it tells you nothing about the company. Ask the recruiter for an email from "
                       "the company's own domain and check that it matches the company website.")
        else:
            if not res["sender"].strip():
                st.caption("No sender was entered, so this is the first email address found in the message.")
            domain_block(domain)

        st.markdown("**Links in the message**")
        hosts = []
        for raw in extract_links(res["message"]):
            host, _ = link_host(raw)
            if host and "." in host and host not in hosts:
                hosts.append(host)
        if not hosts:
            st.info("The message has no links.")
        looked_up = 0
        for host in hosts:
            if domain and not is_free and root_domain(host) == root_domain(domain):
                st.caption(f"{host} is the same website as the sender's domain (shown above).")
            elif is_trusted_link(host):
                st.success(f"**{host}** is a well-known platform. Pages and forms on it can still be "
                           "made by anyone, so check who created the one you were sent.")
            elif host in URL_SHORTENERS:
                st.warning(f"**{host}** is a link shortener that hides where the link really goes. "
                           "OfferGuard does not open it. Ask the sender for the full link.")
            elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                st.error(f"**{host}** is a raw number, not a website name. Real companies do not use "
                         "these. Do not open it.")
            elif looked_up >= 3:
                st.caption(f"{host}: not looked up (OfferGuard checks at most 3 links).")
            else:
                looked_up += 1
                domain_block(host, compact=True)
        st.caption("SPF and DMARC are settings that stop others from faking a company's email. Big "
                   "companies almost always have them, but some small genuine ones do not.")

    # ---------- Report and get help ----------
    with t_help:
        st.markdown("**What triggered the alarm**")
        alarms = [m for m in res["matches"] if m["group"] != "Missing details" and m["points"] > 0]
        if alarms:
            st.markdown("".join(finding_html(m) for m in alarms), unsafe_allow_html=True)
        else:
            st.write("No strong warning signs were found in this message. A low score still does not "
                     "prove the offer is genuine.")
        st.markdown("**If you already paid or shared documents**")
        st.markdown(
            "1. Call **1930**, the national cybercrime helpline, as soon as possible.\n"
            "2. Tell your bank right away and ask them to block or flag the payment.\n"
            "3. File a complaint on the national cybercrime portal.\n"
            "4. If you shared Aadhaar, PAN or passwords, change the passwords and watch your accounts.")
        st.link_button("Report on cybercrime.gov.in", "https://cybercrime.gov.in")
        st.markdown("**Keep the evidence**")
        st.markdown(
            "- Take screenshots of the messages, the sender's number or email, and any payment page.\n"
            "- Save the payment receipt or transaction ID.\n"
            "- Do not delete the chat. Tell your college placement cell and a trusted senior.")

    # ---------- Genuine internships ----------
    with t_genuine:
        st.caption("Trusted places to look instead. Pick a field to update the searches.")
        if "w_field" not in st.session_state:
            st.session_state.w_field = st.session_state.field
        field = st.radio("Field", list(FIELDS), key="w_field", horizontal=True,
                         label_visibility="collapsed")
        st.session_state.field = field
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

    st.button("←  Back to Check an offer", on_click=goto, args=("check",), key="back_bottom")


# ============================================================
# THE PAGE: header, the two-page menu, then the chosen page
# ============================================================
st.markdown('<p class="og-title">🛡️ Offer<span>Guard</span></p>'
            '<p class="og-sub">Paste an internship or job offer. Get a risk score, the exact red flags, '
            'and where to cross-check them.</p>', unsafe_allow_html=True)

page = st.session_state.page
nav1, nav2 = st.columns(2)
nav1.button("1 · Check an offer", on_click=goto, args=("check",), key="nav_check",
            type="primary" if page == "check" else "secondary")
nav2.button("2 · Cross-check", on_click=goto, args=("cross",), key="nav_cross",
            type="primary" if page == "cross" else "secondary")

if page == "cross":
    page_cross()
else:
    page_check()

st.caption("OfferGuard shows warning signs, not a verdict. A low score does not prove an offer is genuine.")
