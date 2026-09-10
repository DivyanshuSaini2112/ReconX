"""FastAPI server for live scan progress dashboard.
Exposes:
  GET  /status    - current scan state summary
  WS   /ws/live   - real-time event stream (JSON lines)
  GET  /report    - final report JSON once scan completes
"""

from fastapi import FastAPI, WebSocket
import asyncio

app = FastAPI(title="NEXUS Live View", version="0.1.0")

_events: list = []  # populated by LangGraph node callbacks


@app.get("/status")
async def status():
    return {"events_count": len(_events), "latest": _events[-1] if _events else None}


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    sent = 0
    while True:
        if sent < len(_events):
            for event in _events[sent:]:
                await websocket.send_json(event)
            sent = len(_events)
        await asyncio.sleep(0.5)
