from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers.analyze import router as analyze_router
from routers.phishing import router as phishing_router
from routers.vulnerability import router as vuln_router
from routers.ioc import router as ioc_router
from routers.incident import router as incident_router
from routers.webscan import router as webscan_router
from services.claude_service import IS_MOCK

app = FastAPI(title="AI Security Suite", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)
app.include_router(phishing_router)
app.include_router(vuln_router)
app.include_router(ioc_router)
app.include_router(incident_router)
app.include_router(webscan_router)


@app.get("/")
def root():
    return {"status": "ok", "app": "AI Security Suite"}


@app.get("/api/mode")
def get_mode():
    return {"mock": IS_MOCK, "mode": "mock" if IS_MOCK else "live"}
