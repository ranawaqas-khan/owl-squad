import re
import dns.resolver
import smtplib
import time
import random
import string
import logging
from statistics import mean
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================
# LOGGING CONFIG
# =========================
logging.basicConfig(
    filename="verifier_debug.log",   # log file name (Railway will show it in console logs too)
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logging.info("✅ Verifier module loaded successfully with debug logging enabled.")

# =========================
# CONFIG
# =========================
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
TIMEOUT = 5
PAUSE_BETWEEN_PROBES = 0.1
MAX_WORKERS_DEFAULT = 20

FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "aol.com", "zoho.com", "yandex.com"
}
DISPOSABLE_PROVIDERS = {
    "tempmail.com", "mailinator.com", "guerrillamail.com", "10minutemail.com"
}
ROLE_PREFIXES = {"info", "admin", "sales", "support", "contact", "hr", "help", "team"}

# =========================
# UTILITIES
# =========================
def random_local(k=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def detect_mx_provider(mx_host: str) -> str:
    h = mx_host.lower()
    if "outlook" in h or "protection" in h:
        return "microsoft365"
    if "google" in h or "aspmx" in h:
        return "google"
    if "pphosted" in h:
        return "proofpoint"
    if "mimecast" in h:
        return "mimecast"
    if "barracuda" in h:
        return "barracuda"
    return "unknown"

def classify_email(local: str, domain: str):
    d = domain.lower()
    if d in FREE_PROVIDERS:
        return "free"
    if any(d.endswith(dp) for dp in DISPOSABLE_PROVIDERS):
        return "disposable"
    if d.endswith(".gov") or d.endswith(".gov.pk"):
        return "government"
    if any(local.lower().startswith(p) for p in ROLE_PREFIXES):
        return "role"
    return "business"

# =========================
# SMTP MULTI-PROBE
# =========================
def smtp_multi_probe(mx: str, target_email: str):
    """Sends 3 probes → fake1, real, fake2 to detect catch-all & timing"""
    domain = target_email.split("@")[1]
    seq = [
        f"{random_local()}@{domain}",
        target_email,
        f"{random_local()}@{domain}"
    ]
    results = []
    try:
        s = smtplib.SMTP(timeout=TIMEOUT)
        s.connect(mx)
        s.helo("bounso.com")
        s.mail("probe@bounso.com")
        logging.debug(f"[{target_email}] SMTP connected → {mx}")

        for addr in seq:
            start = time.perf_counter()
            try:
                code, msg = s.rcpt(addr)
            except Exception as e:
                code, msg = None, str(e)
            latency = round((time.perf_counter() - start) * 1000, 2)
            msg = msg.decode() if isinstance(msg, bytes) else str(msg)
            results.append((addr, code, msg, latency))
            logging.debug(f"[{target_email}] RCPT test → {addr} | code={code} | latency={latency}ms | msg={msg[:120]}")
            time.sleep(PAUSE_BETWEEN_PROBES)

        s.quit()
        logging.debug(f"[{target_email}] SMTP session closed successfully.")
    except Exception as e:
        results.append(("__connect__", None, f"connect_error:{e}", None))
        logging.error(f"[{target_email}] SMTP connection error: {e}")
    return results

# =========================
# ANALYSIS: TIMING + ENTROPY + CATCH-ALL
# =========================
def analyze_entropy_and_catchall(seq):
    try:
        codes = [c for _, c, *_ in seq if c is not None]
        msgs = [m[-80:] for *_, m, _ in seq if isinstance(m, str)]
        latencies = [t for *_, t in seq if isinstance(t, (int, float))]
        entropy = len(set(msgs))
        delta = int(max(latencies) - min(latencies)) if latencies else 0

        fake1, real, fake2 = codes[0], codes[1], codes[2]
        catch_all = (fake1 == 250 and fake2 == 250)
        flat_entropy = (entropy == 1)
        is_catch_all = catch_all or (flat_entropy and real == 250)

        analysis = {
            "entropy": entropy,
            "delta": delta,
            "is_catch_all": is_catch_all,
            "real_code": real,
            "avg_latency": int(mean(latencies)) if latencies else None
        }
        logging.debug(f"Entropy analysis result: {analysis}")
        return analysis
    except Exception as e:
        logging.error(f"Error in analyze_entropy_and_catchall: {e}")
        return {"entropy": 0, "delta": 0, "is_catch_all": False, "real_code": None, "avg_latency": None}

# =========================
# MAIN VERIFY FUNCTION
# =========================
def verify_email(email: str):
    result = {
        "email": email,
        "status": "undeliverable",
        "deliverable": False,
        "verification_score": 0.0,
        "mx_provider": "unknown",
        "mx_records": {"mx": []},
        "smtp": {"code": None, "message": None, "latency_ms": None},
        "details": {
            "email_type": None,
            "is_free_provider": None,
            "is_disposable": None,
            "is_role_based": None,
            "is_government": None,
            "is_catch_all": None
        }
    }

    if not EMAIL_REGEX.match(email or ""):
        result["details"]["reasoning"] = "bad_syntax"
        logging.warning(f"[{email}] Bad syntax detected.")
        return result

    local, domain = email.split("@", 1)
    email_type = classify_email(local, domain)
    result["details"]["email_type"] = email_type
    result["details"]["is_free_provider"] = (email_type == "free")
    result["details"]["is_disposable"] = (email_type == "disposable")
    result["details"]["is_role_based"] = (email_type == "role")
    result["details"]["is_government"] = (email_type == "government")

    # MX Lookup
    try:
        mx_records = [str(r.exchange).rstrip('.') for r in dns.resolver.resolve(domain, "MX")]
        result["mx_records"]["mx"] = mx_records
        result["mx_provider"] = detect_mx_provider(mx_records[0])
        logging.debug(f"[{email}] MX lookup success: {mx_records} → Provider: {result['mx_provider']}")
    except Exception as e:
        result["details"]["reasoning"] = f"no_mx | {e}"
        logging.error(f"[{email}] MX lookup failed: {e}")
        return result

    # SMTP multi-probe
    seq = smtp_multi_probe(mx_records[0], email)
    logging.debug(f"[{email}] SMTP multi-probe raw result: {seq}")

    analysis = analyze_entropy_and_catchall(seq)
    real_code = analysis["real_code"]

    result["details"]["is_catch_all"] = analysis["is_catch_all"]
    result["smtp"]["code"] = real_code
    result["smtp"]["latency_ms"] = analysis["delta"]
    result["smtp"]["message"] = seq[1][2] if len(seq) > 1 else None

    # Decision
    if real_code == 250:
        result["status"] = "deliverable"
        result["deliverable"] = True
        result["verification_score"] = 0.98 if not analysis["is_catch_all"] else 0.85
        result["details"]["reasoning"] = "250_ok"
        logging.info(f"[{email}] ✅ Deliverable (code 250) | Catch-all={analysis['is_catch_all']}")
    elif real_code == 550:
        result["status"] = "undeliverable"
        result["deliverable"] = False
        result["verification_score"] = 0.0
        result["details"]["reasoning"] = "550_hard_fail"
        logging.info(f"[{email}] ❌ Undeliverable (550)")
    else:
        result["status"] = "undeliverable"
        result["verification_score"] = 0.0
        result["details"]["reasoning"] = "smtp_error"
        logging.warning(f"[{email}] ⚠️ SMTP uncertain → code={real_code}, msg={result['smtp']['message']}")

    return result

# =========================
# BULK PARALLEL VERIFICATION
# =========================
def verify_bulk_emails(emails, max_workers=MAX_WORKERS_DEFAULT):
    results = []
    logging.debug(f"Starting bulk verification for {len(emails)} emails with {max_workers} workers.")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(verify_email, e): e for e in emails}
        for f in as_completed(futures):
            try:
                res = f.result()
                results.append(res)
            except Exception as e:
                logging.error(f"Error in thread verifying {futures[f]}: {e}")
    logging.debug("Bulk verification completed.")
    return results
