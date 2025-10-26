from fastapi import FastAPI
from pydantic import BaseModel
from finder import find_valid_email

app = FastAPI(
    title="Bounso Email Finder",
    version="2.0",
    description="AI-assisted email finder with SMTP timing & heuristics"
)


# -------------------------------------------------------
# Request Schema
# -------------------------------------------------------
class FinderRequest(BaseModel):
    first_name: str
    last_name: str
    domain: str


# -------------------------------------------------------
# Health Check
# -------------------------------------------------------
@app.get("/")
def home():
    return {
        "message": "🕵️‍♂️ Bounso Email Finder API is live!",
        "version": "2.0",
        "usage": "POST /find with {first_name, last_name, domain}"
    }


# -------------------------------------------------------
# Main Finder Endpoint
# -------------------------------------------------------
@app.post("/find")
async def find_email(req: FinderRequest):
    """
    Finds the most probable valid email for a person using pattern-based
    generation + single-pass SMTP timing verification.
    """

    try:
        result = find_valid_email(req.first_name, req.last_name, req.domain)

        # Always return full debug info to inspect latency, codes, MX, etc.
        return {
            "input": {
                "first_name": req.first_name,
                "last_name": req.last_name,
                "domain": req.domain
            },
            "status": result.get("status"),
            "valid": result.get("valid"),
            "email": result.get("email"),
            "smtp_code": result.get("smtp_code"),
            "latency": result.get("latency"),
            "reason": result.get("reason"),
            "mx": result.get("mx"),
            "debug": result.get("debug", [])
        }

    except Exception as e:
        # Return internal error info for debugging if verification crashes
        return {
            "status": "error",
            "valid": False,
            "email": None,
            "error": str(e)
        }
