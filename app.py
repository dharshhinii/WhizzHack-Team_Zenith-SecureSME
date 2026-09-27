"""
app.py — FastAPI Backend REST API for non-technical small business vulnerability scanner.
"""
import uuid
import asyncio
from typing import Dict, Any
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from main import build_graph

app = FastAPI(title="Small Business Security Scanner API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory database of scan jobs
SCAN_JOBS: Dict[str, Dict[str, Any]] = {}
graph_app = build_graph()


class ScanRequest(BaseModel):
    url: str
    confirm_authorized: bool


async def run_scan_pipeline(job_id: str, url: str):
    SCAN_JOBS[job_id]["status"] = "RUNNING"
    SCAN_JOBS[job_id]["step"] = "Executing Security Scanners..."

    try:
        # Run graph execution in thread pool to prevent blocking event loop
        loop = asyncio.get_event_loop()
        final_state = await loop.run_in_executor(None, lambda: graph_app.invoke({"url": url}))
        
        SCAN_JOBS[job_id]["status"] = "COMPLETED"
        SCAN_JOBS[job_id]["step"] = "Finished"
        SCAN_JOBS[job_id]["results"] = final_state.get("summary_json", {})
        SCAN_JOBS[job_id]["report_path"] = final_state.get("report_path", "")
    except Exception as e:
        SCAN_JOBS[job_id]["status"] = "FAILED"
        SCAN_JOBS[job_id]["error"] = str(e)


@app.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    if not req.confirm_authorized:
        raise HTTPException(
            status_code=400,
            detail="You must confirm you own or are authorized to test this website."
        )

    url = req.url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    job_id = str(uuid.uuid4())
    SCAN_JOBS[job_id] = {
        "job_id": job_id,
        "url": url,
        "status": "QUEUED",
        "step": "Starting scan...",
        "results": None,
        "error": None
    }

    background_tasks.add_task(run_scan_pipeline, job_id, url)

    return {"job_id": job_id, "status": "QUEUED", "message": "Scan started."}


@app.get("/api/scan/{job_id}")
async def get_scan_status(job_id: str):
    if job_id not in SCAN_JOBS:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return SCAN_JOBS[job_id]


# Serve frontend static assets
import os
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def serve_index():
    from fastapi.responses import FileResponse
    return FileResponse("templates/index.html")
