"""MCP client with multi-transport support.

Connects to MCP servers via stdio, SSE, or HTTP transports.
"""

import asyncio
import json
import logging
import subprocess
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class MCPTransport(str, Enum):
    """MCP transport types."""
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"


@dataclass
class ToolParameter:
    """Parameter definition for an MCP tool."""
    name: str
    type: str
    description: str = ""
    required: bool = True
    enum: list[str] | None = None
    default: Any = None

    # Inferred properties for security testing
    is_path: bool = False
    is_url: bool = False
    is_command: bool = False
    is_query: bool = False


@dataclass
class MCPTool:
    """MCP tool definition."""
    name: str
    description: str
    parameters: list[ToolParameter] = field(default_factory=list)
    input_schema: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_schema(cls, name: str, schema: dict[str, Any]) -> "MCPTool":
        """Parse tool from MCP schema."""
        description = schema.get("description", "")
        input_schema = schema.get("inputSchema", {})

        parameters = []
        props = input_schema.get("properties", {})
        required = set(input_schema.get("required", []))

        for param_name, param_schema in props.items():
            param_type = param_schema.get("type", "string")
            param_desc = param_schema.get("description", "")

            # Infer parameter purpose from name and description
            name_lower = param_name.lower()
            desc_lower = param_desc.lower()

            is_path = any(k in name_lower or k in desc_lower for k in
                         ["path", "file", "directory", "dir", "folder"])
            is_url = any(k in name_lower or k in desc_lower for k in
                        ["url", "uri", "endpoint", "href", "link"])
            is_command = any(k in name_lower or k in desc_lower for k in
                            ["command", "cmd", "exec", "shell", "script"])
            is_query = any(k in name_lower or k in desc_lower for k in
                          ["query", "sql", "search", "filter", "where"])

            parameters.append(ToolParameter(
                name=param_name,
                type=param_type,
                description=param_desc,
                required=param_name in required,
                enum=param_schema.get("enum"),
                default=param_schema.get("default"),
                is_path=is_path,
                is_url=is_url,
                is_command=is_command,
                is_query=is_query,
            ))

        return cls(
            name=name,
            description=description,
            parameters=parameters,
            input_schema=input_schema,
        )


@dataclass
class ToolCallResult:
    """Result of calling an MCP tool."""
    tool_name: str
    arguments: dict[str, Any]
    success: bool
    result: Any = None
    error: str | None = None
    raw_response: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0


class MCPTransportBase(ABC):
    """Base class for MCP transports."""

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection."""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection."""
        pass

    @abstractmethod
    async def send_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send JSON-RPC request and get response."""
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if connected."""
        pass


class StdioTransport(MCPTransportBase):
    """stdio transport - spawns process and communicates via stdin/stdout."""

    def __init__(
        self,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ):
        self.command = command
        self.args = args or []
        self.env = env
        self.cwd = cwd
        self._process: subprocess.Popen | None = None
        self._request_id = 0
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        """Start the MCP server process."""
        import os

        full_env = os.environ.copy()
        if self.env:
            full_env.update(self.env)

        cmd = [self.command] + self.args
        logger.info(f"Starting MCP server: {' '.join(cmd)}")

        self._process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=full_env,
            cwd=self.cwd,
            text=True,
            bufsize=1,  # Line buffered
        )

        # Send initialize request
        init_result = await self.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "mass-mcp-interrogator",
                "version": "1.0.0",
            },
        })

        logger.info(f"MCP server initialized: {init_result}")

        # Send initialized notification
        await self._send_notification("notifications/initialized", {})

    async def disconnect(self) -> None:
        """Stop the MCP server process."""
        if self._process:
            try:
                self._process.stdin.close()
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception as e:
                logger.warning(f"Error stopping MCP process: {e}")
                self._process.kill()
            finally:
                self._process = None

    async def send_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send JSON-RPC request via stdin, read response from stdout."""
        if not self._process or not self._process.stdin or not self._process.stdout:
            raise RuntimeError("Not connected")

        async with self._lock:
            self._request_id += 1
            request = {
                "jsonrpc": "2.0",
                "id": self._request_id,
                "method": method,
            }
            if params:
                request["params"] = params

            # Write request
            request_line = json.dumps(request) + "\n"
            self._process.stdin.write(request_line)
            self._process.stdin.flush()

            # Read response (blocking - run in executor)
            loop = asyncio.get_event_loop()
            response_line = await loop.run_in_executor(
                None, self._process.stdout.readline
            )

            if not response_line:
                stderr = self._process.stderr.read() if self._process.stderr else ""
                raise RuntimeError(f"MCP server closed connection. stderr: {stderr}")

            response = json.loads(response_line)

            if "error" in response:
                raise RuntimeError(f"MCP error: {response['error']}")

            return response.get("result", {})

    async def _send_notification(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> None:
        """Send JSON-RPC notification (no response expected)."""
        if not self._process or not self._process.stdin:
            raise RuntimeError("Not connected")

        notification = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params:
            notification["params"] = params

        notification_line = json.dumps(notification) + "\n"
        self._process.stdin.write(notification_line)
        self._process.stdin.flush()

    def is_connected(self) -> bool:
        return self._process is not None and self._process.poll() is None


class HTTPTransport(MCPTransportBase):
    """HTTP transport - communicates via HTTP POST requests.

    Supports both pure JSON-RPC and Streamable HTTP (SSE responses).
    """

    def __init__(
        self,
        base_url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._request_id = 0
        self._session_id: str | None = None
        self._init_result: dict[str, Any] = {}

    async def connect(self) -> None:
        """Initialize HTTP client and MCP session."""
        # Add required Accept header for Streamable HTTP MCP servers
        default_headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        default_headers.update(self.headers)

        # Don't use base_url - we'll use the full URL in each request
        # to avoid httpx adding trailing slashes
        self._client = httpx.AsyncClient(
            headers=default_headers,
            timeout=self.timeout,
        )

        # Initialize MCP session
        init_result, response_headers = await self._send_request_with_headers("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "mass-mcp-interrogator",
                "version": "1.0.0",
            },
        })

        # Session ID comes from response header, not body
        self._session_id = response_headers.get("mcp-session-id")
        # Store the init result for later retrieval
        self._init_result = init_result
        logger.info(f"MCP HTTP session initialized: {self._session_id}")

        # Send initialized notification
        try:
            await self.send_request("notifications/initialized", {})
        except Exception:
            pass  # Some servers don't require this

    async def disconnect(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
            self._session_id = None

    async def _send_request_with_headers(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        """Send request and return both result and response headers."""
        if not self._client:
            raise RuntimeError("Not connected")

        self._request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
        }
        if params:
            request["params"] = params

        headers = {}
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        response = await self._client.post(
            self.base_url,
            json=request,
            headers=headers,
        )
        response.raise_for_status()

        # Extract response headers
        response_headers = dict(response.headers)

        content_type = response.headers.get("content-type", "")

        # Handle SSE response (text/event-stream)
        if "text/event-stream" in content_type:
            result = await self._parse_sse_response(response)
            return result, response_headers

        # Handle JSON response
        result = response.json()

        if "error" in result:
            raise RuntimeError(f"MCP error: {result['error']}")

        return result.get("result", {}), response_headers

    async def send_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send JSON-RPC request via HTTP POST.

        Handles both JSON and SSE (text/event-stream) responses.
        """
        result, _ = await self._send_request_with_headers(method, params)
        return result

    async def _parse_sse_response(self, response: httpx.Response) -> dict[str, Any]:
        """Parse SSE response and extract the result."""
        content = response.text
        result = {}

        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("data:"):
                data = line[5:].strip()
                if data:
                    try:
                        message = json.loads(data)
                        if "result" in message:
                            result = message.get("result", {})
                        elif "error" in message:
                            raise RuntimeError(f"MCP error: {message['error']}")
                    except json.JSONDecodeError:
                        continue

        return result

    def is_connected(self) -> bool:
        return self._client is not None

    def get_init_result(self) -> dict[str, Any]:
        """Get the result from the initialize call."""
        return self._init_result


class SSETransport(MCPTransportBase):
    """SSE (Server-Sent Events) transport."""

    def __init__(
        self,
        sse_url: str,
        post_url: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ):
        self.sse_url = sse_url
        self.post_url = post_url or sse_url.replace("/sse", "/message")
        self.headers = headers or {}
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._request_id = 0
        self._pending_responses: dict[int, asyncio.Future] = {}
        self._sse_task: asyncio.Task | None = None
        self._connected = False

    async def connect(self) -> None:
        """Connect to SSE endpoint and start listening."""
        self._client = httpx.AsyncClient(
            headers=self.headers,
            timeout=httpx.Timeout(self.timeout, connect=self.timeout),
        )

        # Event to signal when SSE stream is ready
        self._sse_ready = asyncio.Event()

        # Start SSE listener
        self._connect_error = None
        self._sse_task = asyncio.create_task(self._listen_sse())
        self._connected = True

        # Wait for SSE stream to establish (not just a fixed sleep)
        try:
            await asyncio.wait_for(self._sse_ready.wait(), timeout=self.timeout)
        except asyncio.TimeoutError:
            raise RuntimeError(
                f"SSE connection timed out after {self.timeout}s. "
                f"Server may be unreachable or not an SSE MCP endpoint."
            )

        # Check if SSE stream failed during connection
        if self._connect_error:
            err = self._connect_error
            if isinstance(err, httpx.HTTPStatusError):
                status_code = err.response.status_code
                raise RuntimeError(
                    f"SSE endpoint returned HTTP {status_code}. "
                    f"Server may use HTTP streaming transport instead of SSE. "
                    f"Try switching to 'http' transport."
                )
            raise RuntimeError(f"SSE connection failed: {err}")

        # Initialize
        init_result = await self.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "mass-mcp-interrogator",
                "version": "1.0.0",
            },
        })

        logger.info(f"MCP SSE session initialized: {init_result}")

    async def disconnect(self) -> None:
        """Stop SSE listener and close client."""
        self._connected = False

        if self._sse_task:
            self._sse_task.cancel()
            try:
                await self._sse_task
            except asyncio.CancelledError:
                pass
            self._sse_task = None

        if self._client:
            await self._client.aclose()
            self._client = None

    async def _listen_sse(self) -> None:
        """Listen for SSE events."""
        if not self._client:
            return

        try:
            async with self._client.stream("GET", self.sse_url) as response:
                response.raise_for_status()
                # SSE stream connected — signal ready
                current_event = ""
                if hasattr(self, '_sse_ready'):
                    self._sse_ready.set()

                async for line in response.aiter_lines():
                    # Handle SSE event type lines
                    if line.startswith("event:"):
                        current_event = line[6:].strip()
                        continue

                    if not line.startswith("data:"):
                        if line == "":
                            current_event = ""  # Reset event on blank line
                        continue

                    data = line[5:].strip()
                    if not data:
                        continue

                    # Handle MCP SSE protocol "endpoint" event
                    if current_event == "endpoint":
                        # Server tells us where to POST messages
                        endpoint = data
                        if endpoint.startswith("/"):
                            # Relative URL — resolve against SSE URL
                            from urllib.parse import urljoin
                            endpoint = urljoin(self.sse_url, endpoint)
                        self.post_url = endpoint
                        logger.info(f"SSE endpoint set to: {self.post_url}")
                        current_event = ""
                        continue

                    # Handle JSON-RPC response
                    try:
                        message = json.loads(data)
                        request_id = message.get("id")
                        if request_id and request_id in self._pending_responses:
                            self._pending_responses[request_id].set_result(message)
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid SSE JSON: {data}")

                    current_event = ""
        except httpx.HTTPStatusError as e:
            logger.error(f"SSE HTTP error: {e.response.status_code} {e}")
            self._connected = False
            self._connect_error = e
            if hasattr(self, '_sse_ready'):
                self._sse_ready.set()  # Unblock waiter even on error
        except Exception as e:
            logger.error(f"SSE connection error: {e}")
            self._connected = False
            self._connect_error = e
            if hasattr(self, '_sse_ready'):
                self._sse_ready.set()  # Unblock waiter even on error

    async def send_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send request via POST, receive response via SSE."""
        if not self._client:
            raise RuntimeError("Not connected")

        self._request_id += 1
        request_id = self._request_id

        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params:
            request["params"] = params

        # Set up response future
        future: asyncio.Future = asyncio.Future()
        self._pending_responses[request_id] = future

        try:
            # Send request
            response = await self._client.post(self.post_url, json=request)
            response.raise_for_status()

            # Wait for SSE response
            result = await asyncio.wait_for(future, timeout=self.timeout)

            if "error" in result:
                raise RuntimeError(f"MCP error: {result['error']}")

            return result.get("result", {})
        finally:
            self._pending_responses.pop(request_id, None)

    def is_connected(self) -> bool:
        return self._connected


class MCPClient:
    """MCP client for connecting to and interrogating MCP servers."""

    def __init__(self, transport: MCPTransportBase):
        self.transport = transport
        self._tools: list[MCPTool] = []
        self._server_info: dict[str, Any] = {}

    @classmethod
    def stdio(
        cls,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> "MCPClient":
        """Create client with stdio transport."""
        return cls(StdioTransport(command, args, env, cwd))

    @classmethod
    def http(
        cls,
        base_url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> "MCPClient":
        """Create client with HTTP transport."""
        return cls(HTTPTransport(base_url, headers, timeout))

    @classmethod
    def sse(
        cls,
        sse_url: str,
        post_url: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> "MCPClient":
        """Create client with SSE transport."""
        return cls(SSETransport(sse_url, post_url, headers, timeout))

    async def connect(self) -> None:
        """Connect to MCP server."""
        await self.transport.connect()

    async def disconnect(self) -> None:
        """Disconnect from MCP server."""
        await self.transport.disconnect()

    async def __aenter__(self) -> "MCPClient":
        await self.connect()
        return self

    async def __aexit__(self, *args) -> None:
        await self.disconnect()

    async def list_tools(self) -> list[MCPTool]:
        """Enumerate available tools from the MCP server."""
        result = await self.transport.send_request("tools/list")
        tools_data = result.get("tools", [])

        self._tools = []
        for tool_data in tools_data:
            tool = MCPTool.from_schema(
                name=tool_data.get("name", ""),
                schema=tool_data,
            )
            self._tools.append(tool)

        logger.info(f"Discovered {len(self._tools)} tools")
        return self._tools

    @property
    def tools(self) -> list[MCPTool]:
        """Get cached tools list."""
        return self._tools

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ToolCallResult:
        """Call an MCP tool with given arguments."""
        import time

        start = time.perf_counter()

        try:
            result = await self.transport.send_request("tools/call", {
                "name": tool_name,
                "arguments": arguments,
            })

            duration = (time.perf_counter() - start) * 1000

            return ToolCallResult(
                tool_name=tool_name,
                arguments=arguments,
                success=True,
                result=result.get("content", result),
                raw_response=result,
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000

            return ToolCallResult(
                tool_name=tool_name,
                arguments=arguments,
                success=False,
                error=str(e),
                duration_ms=duration,
            )

    async def get_server_info(self) -> dict[str, Any]:
        """Get server capabilities and info."""
        if not self._server_info:
            # Try to get cached init result from transport first
            if hasattr(self.transport, 'get_init_result'):
                self._server_info = self.transport.get_init_result()

            # If still empty, try to initialize (for transports that don't cache)
            if not self._server_info:
                self._server_info = await self.transport.send_request("initialize", {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "mass-mcp-interrogator",
                        "version": "1.0.0",
                    },
                })
        return self._server_info
