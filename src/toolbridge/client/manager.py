"""MCP Client Manager for handling upstream server lifecycles, pooling, and invocations."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
import os
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import (
    CallToolResult,
    CancelledNotification,
    CancelledNotificationParams,
    TextContent,
    ToolListChangedNotification,
)

from toolbridge.client.discovery import ToolDiscoveryEngine
from toolbridge.client.registry import ServerRegistry
from toolbridge.models.server import ServerStatus, TransportType, UpstreamServerConfig

logger = logging.getLogger(__name__)


@dataclass
class _UpstreamWorkerState:
    """Tracks state and dedicated lifecycle task for a connected upstream server."""
    task: asyncio.Task[None]
    stop_event: asyncio.Event
    config: UpstreamServerConfig | None = None
    session: ClientSession | None = None
    timeout_failures: int = 0


class MCPClientManager:
    """Manages the connection lifecycle, discovery, and execution for all upstream MCP servers.

    Each connected upstream server is owned by exactly ONE dedicated asyncio task to ensure
    that anyio cancel scopes (in stdio_client and ClientSession) are entered and exited
    within the same task context, eliminating 'Attempted to exit cancel scope in a different task' errors.
    """

    def __init__(self, registry: ServerRegistry | None = None) -> None:
        self.registry = registry or ServerRegistry()
        self._workers: dict[str, _UpstreamWorkerState] = {}
        self._lock = asyncio.Lock()

    @property
    def _sessions(self) -> dict[str, ClientSession]:
        """Backward-compatible mapping of active sessions."""
        return {s_id: w.session for s_id, w in self._workers.items() if w.session is not None}

    @property
    def active_server_ids(self) -> list[str]:
        """Return list of server IDs with active sessions."""
        return list(self._sessions.keys())

    async def connect_server(self, server_id: str) -> bool:
        """Establish an MCP connection with an upstream server and discover its tools.

        Spawns a dedicated owner task and awaits the initialization handshake in parallel.
        """
        async with self._lock:
            server_info = await self.registry.get_server(server_id)
            if not server_info:
                logger.error(f"Cannot connect: Server '{server_id}' is not registered.")
                return False

            config = server_info.config
            if not config.enabled:
                logger.info(f"Skipping server '{server_id}' (disabled in configuration).")
                return False

            # If already connected, disconnect first for clean reconnection
            if server_id in self._workers:
                await self._disconnect_worker(server_id)

            await self.registry.update_status(server_id, ServerStatus.CONNECTING)
            ready_event = asyncio.Event()
            stop_event = asyncio.Event()

            task = asyncio.create_task(
                self._run_upstream_worker(
                    server_id=server_id,
                    config=config,
                    ready_event=ready_event,
                    stop_event=stop_event,
                ),
                name=f"upstream-worker-{server_id}",
            )

            self._workers[server_id] = _UpstreamWorkerState(
                task=task,
                stop_event=stop_event,
                config=config,
                session=None,
            )

        # Await readiness outside self._lock so multiple servers connect in parallel
        timeout = config.timeout_seconds + 5.0
        try:
            await asyncio.wait_for(ready_event.wait(), timeout=timeout)
            worker = self._workers.get(server_id)
            if worker and worker.session and not task.done():
                logger.info(f"Successfully connected to upstream server '{server_id}'.")
                return True
            else:
                logger.error(f"Worker for '{server_id}' terminated before readiness.")
                async with self._lock:
                    await self._disconnect_worker(server_id)
                return False
        except asyncio.TimeoutError:
            logger.error(f"Connection timeout waiting for server '{server_id}' to start.")
            async with self._lock:
                await self._disconnect_worker(server_id)
            await self.registry.update_status(server_id, ServerStatus.FAILED, error="Connection timeout")
            return False

    async def _run_upstream_worker(
        self,
        server_id: str,
        config: UpstreamServerConfig,
        ready_event: asyncio.Event,
        stop_event: asyncio.Event,
    ) -> None:
        """Dedicated long-lived owner task for stdio_client and ClientSession."""
        if config.transport != TransportType.STDIO:
            err_msg = f"Transport '{config.transport}' is not yet supported in ClientManager."
            logger.error(err_msg)
            await self.registry.update_status(server_id, ServerStatus.FAILED, error=err_msg)
            ready_event.set()
            return

        if not config.command:
            err_msg = f"Server '{server_id}' specifies stdio transport but no command."
            logger.error(err_msg)
            await self.registry.update_status(server_id, ServerStatus.FAILED, error=err_msg)
            ready_event.set()
            return

        safe_env_keys = {
            "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
            "HOME", "USERPROFILE", "PYTHONPATH", "LANG", "LC_ALL",
        }
        base_env = {k: v for k, v in os.environ.items() if k in safe_env_keys}
        env = {**base_env, **config.env, "PYTHONUNBUFFERED": "1"}

        params = StdioServerParameters(
            command=config.command,
            args=config.args,
            env=env,
        )

        async def _notification_handler(notification: Any) -> None:
            # Handle upstream notifications/tools/list_changed
            if isinstance(notification, ToolListChangedNotification):
                logger.info(f"Upstream server '{server_id}' notified tools/list_changed. Refreshing catalog...")
                worker = self._workers.get(server_id)
                if worker and worker.session:
                    try:
                        refreshed_tools = await ToolDiscoveryEngine.discover_tools(worker.session, server_id)
                        await self.registry.register_tools(server_id, refreshed_tools)
                    except Exception as exc:
                        logger.warning(f"Failed to refresh tools for '{server_id}': {exc}")

        try:
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream, message_handler=_notification_handler) as session:
                    await asyncio.wait_for(session.initialize(), timeout=config.timeout_seconds)

                    tools = await ToolDiscoveryEngine.discover_tools(session, server_id)

                    worker = self._workers.get(server_id)
                    if worker:
                        worker.session = session

                    await self.registry.update_status(server_id, ServerStatus.CONNECTED)
                    await self.registry.register_tools(server_id, tools)
                    ready_event.set()

                    # Remain alive until explicitly asked to stop
                    await stop_event.wait()

        except Exception as e:
            logger.error(f"Upstream server '{server_id}' crashed or encountered error: {e}", exc_info=True)
            await self.registry.update_status(server_id, ServerStatus.FAILED, error=str(e))
            await self.registry.clear_server_tools(server_id)
            ready_event.set()
        finally:
            worker = self._workers.get(server_id)
            if worker:
                worker.session = None
            current = await self.registry.get_server(server_id)
            if not current or current.status != ServerStatus.FAILED:
                current = await self.registry.get_server(server_id)
        if not current or current.status != ServerStatus.FAILED:
            await self.registry.update_status(server_id, ServerStatus.DISCONNECTED)
            await self.registry.clear_server_tools(server_id)
            logger.info(f"Cleaned up upstream worker for server '{server_id}'.")

    async def connect_all(self) -> dict[str, bool]:
        """Attempt to connect to all enabled upstream servers in parallel."""
        servers = await self.registry.get_all_servers()
        tasks = [self.connect_server(s.config.id) for s in servers if s.config.enabled]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return {s.config.id: res for s, res in zip(servers, results) if s.config.enabled}

    async def disconnect_server(self, server_id: str) -> None:
        """Disconnect an active upstream server and clean up its resources."""
        async with self._lock:
            await self._disconnect_worker(server_id)

    async def _disconnect_worker(self, server_id: str) -> None:
        """Signal stop to an upstream worker and wait for it to cleanly terminate."""
        worker = self._workers.pop(server_id, None)
        if not worker:
            return

        worker.stop_event.set()
        try:
            await asyncio.wait_for(asyncio.shield(worker.task), timeout=5.0)
        except (asyncio.TimeoutError, Exception) as e:
            logger.warning(f"Upstream worker '{server_id}' did not terminate cleanly within timeout: {e}. Cancelling.")
            worker.task.cancel()
            try:
                await asyncio.wait_for(worker.task, timeout=2.0)
            except Exception:
                pass

        current = await self.registry.get_server(server_id)
        if not current or current.status != ServerStatus.FAILED:
            await self.registry.update_status(server_id, ServerStatus.DISCONNECTED)
        await self.registry.clear_server_tools(server_id)
        logger.info(f"Disconnected server '{server_id}'.")

    async def disconnect_all(self) -> None:
        """Disconnect all active upstream servers concurrently."""
        async with self._lock:
            server_ids = list(self._workers.keys())
        if server_ids:
            await asyncio.gather(*[self.disconnect_server(s_id) for s_id in server_ids], return_exceptions=True)

    async def call_tool(
        self,
        namespaced_tool_name: str,
        arguments: dict[str, Any] | None = None,
        timeout_seconds: float | None = None,
        tool: Any | None = None,
    ) -> CallToolResult:
        """Route an execution request to the appropriate upstream server by namespaced tool name.

        Handles timeouts with CancelledNotification, tracks consecutive failures,
        and recycles repeatedly hanging upstream connections.
        """
        target_tool = tool or await self.registry.get_tool(namespaced_tool_name)
        if not target_tool:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Tool not found: '{namespaced_tool_name}'")],
                is_error=True,
            )

        server_id = target_tool.server_id
        worker = self._workers.get(server_id)
        if not worker or not worker.session:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Upstream server '{server_id}' is disconnected or unavailable.")],
                is_error=True,
            )

        session = worker.session
        timeout = timeout_seconds
        if timeout is None and hasattr(worker, "config") and worker.config is not None:
            cfg_timeout = getattr(worker.config, "timeout_seconds", None)
            if isinstance(cfg_timeout, (int, float)):
                timeout = float(cfg_timeout)
        if timeout is None:
            timeout = 30.0

        try:
            result = await asyncio.wait_for(
                session.call_tool(target_tool.original_name, arguments or {}),
                timeout=timeout,
            )
            # Reset failure counter on successful call
            worker.timeout_failures = 0
            return result
        except asyncio.TimeoutError:
            worker.timeout_failures += 1
            # Send CancelledNotification to upstream as required by MCP protocol
            try:
                await session.send_notification(
                    CancelledNotification(
                        params=CancelledNotificationParams(
                            request_id=f"req_{target_tool.original_name}",
                            reason=f"Call timed out after {timeout} seconds",
                        )
                    )
                )
            except Exception as notif_err:
                logger.debug(f"Could not send CancelledNotification to '{server_id}': {notif_err}")

            # Recycle repeatedly hanging servers
            if worker.timeout_failures >= 3:
                logger.error(
                    f"Server '{server_id}' has timed out {worker.timeout_failures} consecutive times. Recycling connection."
                )
                await self.registry.update_status(server_id, ServerStatus.DEGRADED, error="Repeated timeouts")
                asyncio.create_task(self.connect_server(server_id))

            return CallToolResult(
                content=[TextContent(type="text", text=f"Tool execution timed out after {timeout} seconds.")],
                is_error=True,
            )
        except Exception as e:
            logger.error(f"Upstream execution error on '{server_id}': {e}")
            if worker.task.done():
                await self.registry.update_status(server_id, ServerStatus.FAILED, error=str(e))
            return CallToolResult(
                content=[TextContent(type="text", text=f"Upstream execution error on '{server_id}': {e}")],
                is_error=True,
            )
