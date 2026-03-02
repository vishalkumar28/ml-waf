from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from db.session import init_db
from api.routes_waf import router as waf_router
from api.routes_dashboard import router as dash_router
from websocket.events import ws_router

app = FastAPI(title="ML-WAF Engine", version="1.0.0")

app.add_middleware(CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"])

app.include_router(waf_router,  prefix="/waf")
app.include_router(dash_router, prefix="/api")
app.include_router(ws_router)

@app.on_event("startup")
async def startup():
    init_db()
    print("✅ ML-WAF Engine started")

@app.get("/")
async def health():
    return {"status": "ML-WAF running"}