from app.finder import find_email
from pydantic import BaseModel

class FinderRequest(BaseModel):
    first_name: str
    last_name: str
    domain: str
    max_workers: int = 10

@app.post("/find")
async def find_email_route(req: FinderRequest):
    return find_email(req.first_name, req.last_name, req.domain, req.max_workers)
