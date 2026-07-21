"""WebSocket — real-time dashboard feed"""
import asyncio
import json
import logging
from typing import Dict, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from jose import JWTError

from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["WebSocket"])


class ConnectionManager:
    """Manages active WebSocket connections, scoped by user_id."""

    def __init__(self):
        # user_id -> set of active WebSocket connections for that user
        self._connections: Dict[int, Set[WebSocket]] = {}
        # admin user ids — receive all events regardless of user_id
        self._admins: Set[int] = set()

    def connect(self, user_id: int, ws: WebSocket, is_admin: bool = False):
        self._connections.setdefault(user_id, set()).add(ws)
        if is_admin:
            self._admins.add(user_id)

    def disconnect(self, user_id: int, ws: WebSocket):
        conns = self._connections.get(user_id, set())
        conns.discard(ws)
        if not conns:
            self._connections.pop(user_id, None)
            self._admins.discard(user_id)

    async def broadcast_event(self, event: dict, owner_user_id: int):
        """
        Push event to:
        - the scan owner
        - all connected admins (who see all scans)
        """
        payload = json.dumps(event)
        targets: Set[WebSocket] = set()

        # owner's connections
        targets.update(self._connections.get(owner_user_id, set()))

        # admin connections
        for uid in self._admins:
            if uid != owner_user_id:
                targets.update(self._connections.get(uid, set()))

        dead: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            # find its user_id
            for uid, conns in list(self._connections.items()):
                if ws in conns:
                    self.disconnect(uid, ws)
                    break

    @property
    def connection_count(self) -> int:
        return sum(len(c) for c in self._connections.values())


# Module-level singleton — shared across all request handlers in this process
manager = ConnectionManager()


def _auth_ws(token: str):
    """Decode JWT and return (user_id, role) or raise ValueError."""
    from jose import jwt
    from app.database import SessionLocal
    from app.models.user import User
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            raise ValueError("no sub")
        role = payload.get("role", "viewer")
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.username == username).first()
            if user is None or not user.is_active:
                raise ValueError("user not found or inactive")
            return user.id, role
        finally:
            db.close()
    except (JWTError, Exception) as exc:
        raise ValueError(str(exc))


@router.websocket("/api/ws/feed")
async def ws_feed(
    websocket: WebSocket,
    token: str = Query(..., description="JWT access token"),
):
    """
    Real-time scan event feed.

    Connect with:
        wss://<host>/api/ws/feed?token=<jwt>

    Messages are JSON objects:
        {"type": "scan_complete", "scan": {id, risk_level, verdict, source, created_at, user_id}}
        {"type": "ping"}
    """
    try:
        user_id, role = _auth_ws(token)
    except ValueError as exc:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        logger.warning("WS auth rejected: %s", exc)
        return

    is_admin = role in ("ADMIN", "SUPERADMIN", "ORG_ADMIN", "admin", "superadmin")
    await websocket.accept()
    manager.connect(user_id, websocket, is_admin=is_admin)
    logger.info("WS connected user_id=%d admin=%s total=%d", user_id, is_admin, manager.connection_count)

    try:
        # Keep the connection alive with server-side pings every 25 s.
        # The client should respond with any message to reset the timer;
        # if the socket closes, WebSocketDisconnect is raised.
        while True:
            await asyncio.sleep(25)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("WS loop ended for user_id=%d: %s", user_id, exc)
    finally:
        manager.disconnect(user_id, websocket)
        logger.info("WS disconnected user_id=%d total=%d", user_id, manager.connection_count)
