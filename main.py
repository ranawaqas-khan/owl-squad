from fastapi import FastAPI
from pydantic import BaseModel
from finder import find_valid_email

app = FastAPI(
    title="Bounso Email Finder",
    version="1.0",
    description="Finds valid emails using pattern-based verification"
)

class FinderRequest(BaseModel):
    first_name: str
    last_name: str
    domain: str

@app.get("/")
def home():
    return {"message": "🕵️‍♂️ Bounso Email Finder API is live!", "version": "1.0"}

@app.post("/find")
async def find_email(req: FinderRequest):
    result = find_valid_email(req.first_name, req.last_name, req.domain)
    if result:
        return {
            "status": "found",
            "valid": True,
            "email": result["email"]
        }
    else:
        return {
            "status": "not_found",
            "valid": False,
            "email": None
        }
