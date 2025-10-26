import re, dns.resolver, smtplib, time, random, string, logging, sys
from statistics import mean, stdev

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
TIMEOUT = 5
PAUSE = 0.1

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def rand_local(n=8): return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def get_mx(domain):
    try:
        records = [str(r.exchange).rstrip('.') for r in dns.resolver.resolve(domain, "MX")]
        logging.debug(f"✅ MX for {domain}: {records}")
        return records[0]
    except Exception as e:
        logging.error(f"❌ MX lookup failed for {domain}: {e}")
        return None

def smtp_check(mx_host, email):
    """Do one RCPT test and measure latency"""
    try:
        server = smtplib.SMTP(timeout=TIMEOUT)
        server.connect(mx_host)
        server.helo("gmail.com")
        server.mail("probe@bounso.com")
        t0 = time.perf_counter()
        code, msg = server.rcpt(email)
        latency = (time.perf_counter() - t0) * 1000
        msg = msg.decode() if isinstance(msg, bytes) else str(msg)
        server.quit()
        return {"code": code, "msg": msg, "latency": round(latency, 2)}
    except Exception as e:
        logging.error(f"SMTP error for {email}: {e}")
        return {"code": None, "msg": str(e), "latency": None}

# ---------------------------------------------------------------------
# Core verification
# ---------------------------------------------------------------------
def verify_email(email):
    result = {
        "email": email,
        "deliverable": False,
        "status": "undeliverable",
        "mx": None,
        "latency": None,
        "reason": None
    }

    if not EMAIL_RE.match(email):
        result["reason"] = "invalid_format"
        return result

    local, domain = email.split("@", 1)
    mx_host = get_mx(domain)
    if not mx_host:
        result["reason"] = "no_mx"
        return result

    check = smtp_check(mx_host, email)
    result.update({"mx": mx_host, "latency": check["latency"], "smtp_code": check["code"], "smtp_msg": check["msg"]})

    if check["code"] == 250:
        result["deliverable"] = True
        result["status"] = "deliverable"
        result["reason"] = "250_ok"
    elif check["code"] == 550:
        result["reason"] = "550_rejected"
    else:
        result["reason"] = "smtp_error"

    logging.debug(f"🔍 {email} → {result['status']} ({result['reason']}) latency={result['latency']}ms")
    return result


# ---------------------------------------------------------------------
# Batch comparison heuristic
# ---------------------------------------------------------------------
def verify_batch(candidates):
    """
    Test all candidates once each.
    Detect likely real one on catch-all domains by timing variance.
    """
    results = []
    for e in candidates:
        res = verify_email(e)
        results.append(res)
        time.sleep(PAUSE)

    # collect latencies
    lats = [r["latency"] for r in results if r["latency"]]
    avg = mean(lats) if lats else None
    dev = stdev(lats) if len(lats) > 1 else 0

    logging.debug(f"🧮 Timing stats: avg={avg:.2f if avg else 0}ms dev={dev:.2f}")

    # heuristic: one email slower by >2× stdev = likely real on catch-all
    chosen = None
    if dev and dev > 0:
        threshold = avg + 2 * dev
        outliers = [r for r in results if r["latency"] and r["latency"] > threshold]
        if outliers:
            chosen = outliers[0]

    # fallback: first true deliverable
    if not chosen:
        deliverables = [r for r in results if r["deliverable"]]
        chosen = deliverables[0] if deliverables else None

    return {"results": results, "chosen": chosen}
