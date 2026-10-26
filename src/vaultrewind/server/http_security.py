"""Bounded request bodies, including HTTP chunked requests."""
from starlette.responses import JSONResponse

from .errors import error_body


class BoundedBody:
    def __init__(self, app, limit=6 * 1024 * 1024):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        chunks, length = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            block = message.get("body", b"")
            length += len(block)
            if length > self.limit:
                response = JSONResponse(status_code=413, content=error_body("VALIDATION_ERROR"),
                                        headers={"Cache-Control": "no-store"})
                return await response(scope, receive, send)
            chunks.append(block)
            if not message.get("more_body", False):
                break
        consumed = False
        async def bounded_receive():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()
        await self.app(scope, bounded_receive, send)


class SanitizedUnexpectedErrors:
    """Do not let unexpected exception strings reach ASGI access/error logging."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        started = False
        async def tracked_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)
        try:
            await self.app(scope, receive, tracked_send)
        except Exception:  # noqa: BLE001 - deliberately erase unsafe exception strings at the HTTP boundary
            import logging
            from uuid import uuid4
            correlation = str(uuid4())
            logging.getLogger("vaultrewind.api").error("API_REQUEST_FAILED correlation_id=%s", correlation)
            if not started:
                response = JSONResponse(status_code=503, content=error_body("INTERNAL_ERROR"),
                    headers={"Cache-Control": "no-store", "X-Request-ID": correlation})
                await response(scope, receive, send)
            else:
                # A failed download stays truncated; the client must not treat it as a valid artifact.
                try:
                    await send({"type": "http.response.body", "body": b"", "more_body": False})
                except Exception:  # noqa: BLE001 - transport failure contains no useful public diagnostic
                    logging.getLogger("vaultrewind.api").warning("API_RESPONSE_TRUNCATED correlation_id=%s", correlation)
