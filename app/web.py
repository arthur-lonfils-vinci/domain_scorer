# app/web.py

from fastapi import FastAPI, Query

from app.analyzers.domain_analyzer import analyze_domain
from app.analyzers.email_analyzer import analyze_email

app = FastAPI(
    title="Threat Scoring API",
    version="2.0.0",
    description="Multi-layer threat scoring for domains and emails"
)


@app.get("/api/v1/score/domain/{domain}")
def score_domain_route(domain: str):
    return analyze_domain(domain)


@app.get("/api/v1/score/email/{email}")
def score_email_route(email: str):
    return analyze_email(email)


@app.get("/api/v1/score")
def score_auto(identifier: str = Query(..., description="Domain or email")):
    if "@" in identifier:
        return analyze_email(identifier)
    return analyze_domain(identifier)
