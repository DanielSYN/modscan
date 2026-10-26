"""Web interface: upload a jar, get a report, optionally get Claude's explanation using your own key.

Run with: uvicorn modscan.web.app:app
"""

import asyncio
import json
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from modscan import summary
from modscan.scanner import ScanError, scan_bytes

STATIC_DIR = Path(__file__).parent / "static"
MAX_UPLOAD_BYTES = 64 * 1024 * 1024
MAX_REPORT_BYTES = 256 * 1024
SCANS_PER_MINUTE = 10
SUMMARIES_PER_MINUTE = 6
CONCURRENT_SCANS = 2

# The page shows text taken from possibly malicious files and holds the user's API key, so it
# allows no inline scripts and no third-party anything: injected markup couldn't run or phone home.
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

app = FastAPI(title="ModScan", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
scan_slots = asyncio.Semaphore(CONCURRENT_SCANS)


class RateLimiter:
    """Sliding window per key, in memory. Use Redis once there's more than one server process."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float = 60) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= now - window:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def read_capped(request: Request, limit: int, too_large: str) -> bytes:
    """Read the request body, refusing anything over the limit before it's all in memory."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, too_large)
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise HTTPException(413, too_large)
    return bytes(body)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/scan")
async def scan(request: Request, filename: str = "upload.jar"):
    """The file is sent as the raw request body: no multipart parsing, no temporary files on disk."""
    if not limiter.allow(f"scan:{client_ip(request)}", SCANS_PER_MINUTE):
        raise HTTPException(429, "Too many scans. Wait a minute and try again.")
    data = await read_capped(request, MAX_UPLOAD_BYTES,
                             f"That file is too large. The limit is {MAX_UPLOAD_BYTES // 2**20} MB.")
    if not data:
        raise HTTPException(400, "Choose a file to scan.")
    async with scan_slots:  # scanning is CPU-heavy; don't let a burst of uploads starve the server
        try:
            report = await run_in_threadpool(scan_bytes, data, filename)
        except ScanError as exc:
            raise HTTPException(415, str(exc))
    return report.to_dict()


@app.post("/api/summary")
async def explain(request: Request):
    """The user's own Anthropic key arrives in a header, is used for this one call, and is then
    dropped. It is never stored, logged, or included in any response or error message."""
    if not limiter.allow(f"summary:{client_ip(request)}", SUMMARIES_PER_MINUTE):
        raise HTTPException(429, "Too many requests. Wait a minute and try again.")
    api_key = request.headers.get("x-anthropic-key", "").strip()
    if not api_key:
        raise HTTPException(400, "Enter your Anthropic API key to get an explanation.")
    raw = await read_capped(request, MAX_REPORT_BYTES, "That report is too large to summarise.")
    try:
        report = json.loads(raw)
    except ValueError:
        raise HTTPException(400, "The report isn't valid JSON.")
    if not isinstance(report, dict):
        raise HTTPException(400, "The report isn't valid.")
    try:
        text = await run_in_threadpool(summary.summarise, report, api_key)
    except summary.SummaryError as exc:
        raise HTTPException(exc.status, str(exc))
    return {"summary": text, "model": summary.MODEL}
