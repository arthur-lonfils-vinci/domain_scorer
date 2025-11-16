from fastapi import FastAPI, HTTPException
from app.features import hybrid_score

app = FastAPI(title="Domain Scorer PoC")

@app.get("/score/{domain}")
def score_domain(domain: str):
    result = hybrid_score(domain)
    if result["score"] is None:
        raise HTTPException(status_code=400, detail=result["reasons"][0])
    return result
