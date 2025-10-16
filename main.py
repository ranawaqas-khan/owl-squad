from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
import re, dns.resolver, smtplib, time, random, string
from statistics import mean
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================
# FASTAPI INIT
# =========================
app = FastAPI(
    title="Owl Squad Email Finder",
    version="1.0",
    description="Finds real email using full SMTP verification with entropy + catch-all detection"
)

# =========================
# ORIGINAL VERIFICATION LOGIC (AS PROVIDED)
# =========================
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
TIMEOUT = 5
PAUSE_BETWEEN_PROBES = 0.1
MAX_WORKERS_DEFAULT = 20

FREE_PROVIDERS = {
    "gmail.com","yahoo.com","outlook.com","hotmail.com",
    "icloud.com","aol.com","zoho.com","yandex.com"
}
DISPOSABLE_PROVIDERS = {
    "tempmail.com","mailinator.com","guerrillamail.com","10minutemail.com"
}
ROLE_PREFIXES = {"info","admin","sales","support","contact","hr","help","team"}

def random_local(k=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def detect_mx_provider(mx_host:str)->str:
    h = mx_host.lower()
    if "outlook" in h or "protection" in h:  return "microsoft365"
    if "google" in h or "aspmx" in h:        return "google"
    if "pphosted" in h:                      return "proofpoint"
    if "mimecast" in h:                      return "mimecast"
    if "barracuda" in h:                     return "barracuda"
    return "unknown"

def classify_email(local:str, domain:str):
    d = domain.lower()
    if d in FREE_PROVIDERS: return "free"
    if any(d.endswith(dp) for dp in DISPOSABLE_PROVIDERS): return "disposable"
    if d.endswith(".gov") or d.endswith(".gov.pk"): return "government"
    if any(local.lower().startswith(p) for p in ROLE_PREFIXES): return "role"
    return "business"

def smtp_multi_probe(mx:str, target_email:str):
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
        for addr in seq:
            start = time.perf_counter()
            try:
                code, msg = s.rcpt(addr)
            except Exception as e:
                code, msg = None, str(e)
            latency = round((time.perf_counter() - start) * 1000, 2)
            msg = msg.decode() if isinstance(msg, bytes) else str(msg)
            results.append((addr, code, msg, latency))
            time.sleep(PAUSE_BETWEEN_PROBES)
        s.quit()
    except Exception as e:
        results.append(("__connect__", None, f"connect_error:{e}", None))
    return results

def analyze_entropy_and_catchall(seq):
    codes = [c for _, c, *_ in seq if c is not None]
    msgs = [m[-80:] for *_, m, _ in seq if isinstance(m, str)]
    latencies = [t for *_, t in seq if isinstance(t, (int, float))]
    entropy = len(set(msgs))
    delta = int(max(latencies) - min(latencies)) if latencies else 0
    fake1, real, fake2 = codes[0], codes[1], codes[2]
    catch_all = (fake1 == 250 and fake2 == 250)
    flat_entropy = (entropy == 1)
    is_catch_all = catch_all or (flat_entropy and real == 250)
    return {
        "entropy": entropy,
        "delta": delta,
        "is_catch_all": is_catch_all,
        "real_code": real,
        "avg_latency": int(mean(latencies)) if latencies else None
    }

def verify_email(email:str):
    result = {
        "email": email,
        "status": "undeliverable",
        "deliverable": False,
        "verification_score": 0.0,
        "mx_provider": "unknown",
        "mx_records": {"mx": []},
        "smtp": {"code": None, "message": None, "latency_ms": None},
        "details": {}
    }

    if not EMAIL_REGEX.match(email or ""):
        result["details"]["reasoning"] = "bad_syntax"
        return result

    local, domain = email.split("@", 1)
    email_type = classify_email(local, domain)
    result["details"]["email_type"] = email_type

    try:
        mx_records = [str(r.exchange).rstrip('.') for r in dns.resolver.resolve(domain, "MX")]
        result["mx_records"]["mx"] = mx_records
        result["mx_provider"] = detect_mx_provider(mx_records[0])
    except Exception as e:
        result["details"]["reasoning"] = f"no_mx | {e}"
        return result

    seq = smtp_multi_probe(mx_records[0], email)
    analysis = analyze_entropy_and_catchall(seq)
    real_code = analysis["real_code"]

    result["details"]["is_catch_all"] = analysis["is_catch_all"]
    result["smtp"]["code"] = real_code
    result["smtp"]["latency_ms"] = analysis["delta"]
    result["smtp"]["message"] = seq[1][2] if len(seq) > 1 else None

    if real_code == 250:
        result["status"] = "deliverable"
        result["deliverable"] = True
        result["verification_score"] = 0.98 if not analysis["is_catch_all"] else 0.85
        result["details"]["reasoning"] = "250_ok"
    elif real_code == 550:
        result["details"]["reasoning"] = "550_hard_fail"
    else:
        result["details"]["reasoning"] = "smtp_error"

    return result

def verify_bulk_emails(emails, max_workers=MAX_WORKERS_DEFAULT):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(verify_email, e): e for e in emails}
        for f in as_completed(futures):
            results.append(f.result())
    return results

# =========================
# EMAIL FINDER LOGIC
# =========================
def clean_name(full_name: str):
    return [re.sub(r'[^a-zA-Z]', '', p).lower() for p in full_name.strip().split() if p]

def generate_patterns(full_name: str, domain: str):
    parts = clean_name(full_name)
    if not parts: return []
    first, last = parts[0], parts[-1]
    initials = ''.join(p[0] for p in parts)
    patterns = [
        f"{first}@{domain}",
        f"{last}@{domain}",
        f"{first}.{last}@{domain}",
        f"{first}{last}@{domain}",
        f"{first[0]}{last}@{domain}",
        f"{first}.{last[0]}@{domain}",
        f"{first[0]}.{last}@{domain}",
        f"{initials}@{domain}",
        f"{first[:3]}{last}@{domain}",
        f"{first}{last[:2]}@{domain}",
    ]
    return list(dict.fromkeys(patterns))

GENERAL_ADDRESSES = ["support","help","team","info","contact","hello","sales","admin"]

def find_email_for_person(full_name: str, domain: str, batch_size:int=10, max_workers:int=20):
    domain = domain.lower().replace("www.", "")
    candidates = generate_patterns(full_name, domain)
    tried = []

    for i in range(0, len(candidates), batch_size):
        batch = candidates[i:i+batch_size]
        tried.extend(batch)
        results = verify_bulk_emails(batch, max_workers=max_workers)
        for r in results:
            if r.get("deliverable"):
                return {"status":"found","email":r["email"],"type":"personal","record":r,"tried":tried}

    general = [f"{g}@{domain}" for g in GENERAL_ADDRESSES]
    tried.extend(general)
    for i in range(0, len(general), batch_size):
        batch = general[i:i+batch_size]
        results = verify_bulk_emails(batch, max_workers=max_workers)
        for r in results:
            if r.get("deliverable"):
                return {"status":"found_company","email":r["email"],"type":"company","record":r,"tried":tried}

    return {"status":"not_found","email":None,"tried":tried}

# =========================
# FASTAPI ENDPOINT
# =========================
class FinderRequest(BaseModel):
    full_name: str
    domain: str
    batch_size: int = 10
    max_workers: int = 20

@app.get("/")
def home():
    return {"message": "🦉 Owl Squad Email Finder is Live", "version": "1.0"}

@app.post("/find")
async def find_email(req: FinderRequest):
    result = find_email_for_person(req.full_name, req.domain, req.batch_size, req.max_workers)
    return result
