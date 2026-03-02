from fastapi import APIRouter, Request, BackgroundTasks, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from db.session import get_db
from db.models import RequestLog, Classification, BypassAttempt, RetrainQueue
from interceptor.request_parser import extract_payload
from ml.inference import InferenceEngine
from bypass.detector import BypassDetector
import uuid, redis, json, os

router  = APIRouter()
engine  = InferenceEngine()
bypass  = BypassDetector()
r_client = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))

@router.post("/inspect")
async def inspect(request: Request,
                   bg: BackgroundTasks,
                   db: Session = Depends(get_db)):

    data    = await extract_payload(request)
    payload = data["full_payload"]
    result  = engine.predict(payload)
    bp      = bypass.analyze(data["body"], result)

    req_id = str(uuid.uuid4())
    bg.add_task(log_to_db, req_id, data, result, bp, db)
    bg.add_task(publish_ws_event, req_id, data, result)

    if result["decision"] == "BLOCK":
        return JSONResponse(status_code=403, content={
            "blocked":    True,
            "attack_type": result["attack_type"],
            "confidence":  result["confidence"],
            "message":    "Request blocked by ML-WAF",
        })

    return {"status": "allowed", "request_id": req_id}

def log_to_db(req_id, data, result, bp, db):
    log = RequestLog(
        id=req_id, client_ip=data["client_ip"],
        method=data["method"], path=data["path"],
        query_str=data["query"], body=data["body"],
        user_agent=data["user_agent"])
    db.add(log)
    clf = Classification(
        request_id=req_id, decision=result["decision"],
        confidence=result["confidence"], attack_type=result["attack_type"],
        model_ver=result["model_version"])
    db.add(clf)
    if bp["is_bypass_attempt"]:
        db.add(BypassAttempt(
            request_id=req_id,
            bypass_flags=bp["bypass_flags"],
            normalized_payload=bp["normalized_payload"]))
        db.add(RetrainQueue(
            payload=data["full_payload"], label=1, source="bypass_detected"))
    db.commit()

def publish_ws_event(req_id, data, result):
    event = {
        "request_id": req_id,
        "client_ip":  data["client_ip"],
        "path":       data["path"],
        "decision":   result["decision"],
        "attack_type":result["attack_type"],
        "confidence": result["confidence"],
    }
    r_client.publish("waf_events", json.dumps(event))