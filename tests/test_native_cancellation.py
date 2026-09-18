"""Cancellation crosses the real Cython/Go/network boundary, including under -race."""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import osvpy
from explore_toolkit.images import registry_resources


@pytest.mark.parametrize("stage", ["manifest", "layer"])
@pytest.mark.parametrize(
    "action", ["cancel", "asyncio_timeout", "wait_for", "task_group", "cross_thread"]
)
def test_native_cancellation_closes_network(stage: str, action: str) -> None:
    entered, closed = threading.Event(), threading.Event()
    resources = registry_resources()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = resources.get(self.path)
            if body is None:
                self.send_error(404)
                return
            pause = (
                stage == "manifest" and self.path.endswith("/manifests/latest")
            ) or (stage == "layer" and body.startswith(b"\x1f\x8b"))
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header(
                "Content-Type",
                "application/octet-stream"
                if "/blobs/" in self.path
                else json.loads(body).get("mediaType", "application/json"),
            )
            self.end_headers()
            if pause:
                entered.set()
                self.connection.settimeout(10)
                try:
                    disconnected = self.connection.recv(1) == b""
                except ConnectionResetError:
                    disconnected = True
                if disconnected:
                    closed.set()
            else:
                self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    async def run(image: str) -> None:
        if action == "cancel":
            task = asyncio.create_task(osvpy.scan(image))
            assert await asyncio.to_thread(entered.wait, 10)
            task.cancel()
            asyncio.get_running_loop().call_soon(task.cancel)
            asyncio.get_running_loop().call_soon(task.cancel)
            with pytest.raises(asyncio.CancelledError):
                await task
        elif action == "wait_for":
            task = asyncio.create_task(osvpy.scan(image))
            assert await asyncio.to_thread(entered.wait, 10)
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(task, 0)
        elif action == "task_group":

            async def fail() -> None:
                assert await asyncio.to_thread(entered.wait, 10)
                raise ValueError("sibling failed")

            with pytest.raises(ExceptionGroup):  # noqa: PT012 -- TaskGroup cancels the native scan
                async with asyncio.TaskGroup() as group:
                    group.create_task(osvpy.scan(image))
                    group.create_task(fail())
        elif action == "cross_thread":
            task = asyncio.create_task(osvpy.scan(image))
            assert await asyncio.to_thread(entered.wait, 10)
            loop = asyncio.get_running_loop()
            await asyncio.to_thread(lambda: loop.call_soon_threadsafe(task.cancel))
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            with pytest.raises(TimeoutError):  # noqa: PT012 -- expire only after native network admission
                async with asyncio.timeout(None) as timeout:
                    task = asyncio.create_task(osvpy.scan(image))
                    assert await asyncio.to_thread(entered.wait, 10)
                    timeout.reschedule(asyncio.get_running_loop().time())
                    await task
        assert entered.is_set()
        assert await asyncio.to_thread(closed.wait, 10)
        assert (await osvpy.scan()).complete
        assert (await osvpy.scan("BAD IMAGE")).errors[0][1].code == "invalid_image"

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            asyncio.run(run(f"127.0.0.1:{server.server_port}/fixture:latest"))
        finally:
            server.shutdown()
            thread.join()
