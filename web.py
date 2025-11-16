from fastapi import FastAPI, HTTPException, Query
from app.features import hybrid_score
from app.email_features import email_score

app = FastAPI(title="Threat Scoring API", version="1.0.0")


def detect_type(identifier: str):
    if "@" in identifier:
        return "email"
    return "domain"


# ----------------------------------------------------
# Scoring Routes
# ----------------------------------------------------

@app.get("/api/v1/score/domain/{domain}")
def score_domain(domain: str):
    try:
        return hybrid_score(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/score/email/{email}")
def score_email(email: str):
    try:
        return email_score(email)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/score")
def score_auto(identifier: str = Query(..., description="Domain or email")):
    """
    Auto-detect scoring endpoint:
    - emails use email scoring
    - domains use domain scoring
    """
    try:
        if "@" in identifier:
            return email_score(identifier)
        return hybrid_score(identifier)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
