"""Controlled GitHub MCP Server exposing read-only repository, issue, and search tools."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Mapping
import httpx

from mcp.server.lowlevel.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)

TOOL_GET_REPOSITORY = Tool(
    name="get_repository",
    description="Retrieve metadata for a GitHub repository (description, stars, forks, default branch).",
    input_schema={
        "type": "object",
        "properties": {
            "owner": {
                "type": "string",
                "description": "The account owner of the repository (e.g. 'octocat').",
            },
            "repo": {
                "type": "string",
                "description": "The name of the repository (e.g. 'Hello-World').",
            },
        },
        "required": ["owner", "repo"],
    },
)

TOOL_LIST_ISSUES = Tool(
    name="list_issues",
    description="List issues for a repository with state filtering (open, closed, all).",
    input_schema={
        "type": "object",
        "properties": {
            "owner": {
                "type": "string",
                "description": "The account owner of the repository.",
            },
            "repo": {
                "type": "string",
                "description": "The name of the repository.",
            },
            "state": {
                "type": "string",
                "description": "Issue state filter ('open', 'closed', 'all'). Default is 'open'.",
                "enum": ["open", "closed", "all"],
                "default": "open",
            },
            "per_page": {
                "type": "integer",
                "description": "Number of issues to return (1-100). Default is 30.",
                "default": 30,
                "minimum": 1,
                "maximum": 100,
            },
        },
        "required": ["owner", "repo"],
    },
)

TOOL_SEARCH_REPOSITORIES = Tool(
    name="search_repositories",
    description="Search for GitHub repositories using query keywords.",
    input_schema={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search keyword or query qualifier (e.g. 'language:python topic:mcp').",
            },
            "per_page": {
                "type": "integer",
                "description": "Number of results to return (1-50). Default is 10.",
                "default": 10,
                "minimum": 1,
                "maximum": 50,
            },
        },
        "required": ["query"],
    },
)

ALL_GITHUB_TOOLS: list[Tool] = [
    TOOL_GET_REPOSITORY,
    TOOL_LIST_ISSUES,
    TOOL_SEARCH_REPOSITORIES,
]


class GitHubMCPServer:
    """Controlled GitHub MCP Server using GitHub REST API v3."""

    def __init__(
        self,
        token: str | None = None,
        base_url: str = "https://api.github.com",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Initialize with optional personal access token and HTTP client."""
        self.token = token if token is not None else os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN", "").strip()
        self.base_url = base_url.rstrip("/")
        self._custom_client = client
        self._internal_client: httpx.AsyncClient | None = None
        self.server = Server(
            name="toolbridge-github",
            version="0.1.0",
            on_list_tools=self._handle_list_tools,
            on_call_tool=self._handle_call_tool,
        )

    def _get_client(self) -> httpx.AsyncClient:
        """Return active custom client or get/create pooled internal client."""
        if self._custom_client is not None:
            return self._custom_client
        if self._internal_client is None or self._internal_client.is_closed:
            self._internal_client = httpx.AsyncClient(
                timeout=10.0,
                limits=httpx.Limits(max_keepalive_connections=10, max_connections=20, keepalive_expiry=30.0),
            )
        return self._internal_client

    async def aclose(self) -> None:
        """Close internal pooled client session."""
        if self._internal_client is not None and not self._internal_client.is_closed:
            await self._internal_client.aclose()
            self._internal_client = None

    def _get_headers(self) -> dict[str, str]:
        """Build request headers with secure authentication."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ToolBridge-MCP-Gateway/0.1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _handle_list_tools(
        self,
        ctx: ServerRequestContext,
        params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        """Return available GitHub tools."""
        return ListToolsResult(tools=ALL_GITHUB_TOOLS)

    async def _handle_call_tool(
        self,
        ctx: ServerRequestContext,
        params: CallToolRequestParams,
    ) -> CallToolResult:
        """Route tool calls to secured GitHub API handlers."""
        tool_name = params.name
        args = params.arguments or {}

        try:
            if tool_name == "get_repository":
                return await self.tool_get_repository(args)
            elif tool_name == "list_issues":
                return await self.tool_list_issues(args)
            elif tool_name == "search_repositories":
                return await self.tool_search_repositories(args)
            else:
                return self._error_result(f"Unknown GitHub tool: '{tool_name}'")
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            if status == 401:
                return self._error_result("GitHub Authentication Error (401): Bad credentials or token expired.")
            elif status == 403:
                return self._error_result(
                    "GitHub Forbidden (403): API rate limit exceeded or insufficient token scopes."
                )
            elif status == 404:
                return self._error_result(f"GitHub Resource Not Found (404): {e.request.url.path}")
            else:
                return self._error_result(f"GitHub API Error ({status}): {e.response.text}")
        except httpx.RequestError as e:
            return self._error_result(f"GitHub Network Request Error: {e}")
        except Exception as e:
            return self._error_result(f"Execution Error: {e}")

    # --- Tool Handlers ---

    async def tool_get_repository(self, args: Mapping[str, Any]) -> CallToolResult:
        """Fetch repository details."""
        owner = args.get("owner")
        repo = args.get("repo")
        if not owner or not repo:
            return self._error_result("Missing required arguments: 'owner' and 'repo' are required.")

        url = f"{self.base_url}/repos/{owner}/{repo}"
        data = await self._send_request("GET", url)

        summary = {
            "name": data.get("full_name"),
            "description": data.get("description"),
            "html_url": data.get("html_url"),
            "stars": data.get("stargazers_count"),
            "forks": data.get("forks_count"),
            "open_issues_count": data.get("open_issues_count"),
            "default_branch": data.get("default_branch"),
            "language": data.get("language"),
            "private": data.get("private"),
        }
        return self._success_result(json.dumps(summary, indent=2))

    async def tool_list_issues(self, args: Mapping[str, Any]) -> CallToolResult:
        """List repository issues."""
        owner = args.get("owner")
        repo = args.get("repo")
        if not owner or not repo:
            return self._error_result("Missing required arguments: 'owner' and 'repo' are required.")

        state = str(args.get("state", "open"))
        per_page = min(max(int(args.get("per_page", 30)), 1), 100)

        url = f"{self.base_url}/repos/{owner}/{repo}/issues"
        params = {"state": state, "per_page": per_page}
        data = await self._send_request("GET", url, params=params)

        issues = []
        for item in data:
            # Skip pull requests (GitHub API returns PRs as issues)
            if "pull_request" in item:
                continue
            issues.append({
                "number": item.get("number"),
                "title": item.get("title"),
                "state": item.get("state"),
                "author": item.get("user", {}).get("login"),
                "html_url": item.get("html_url"),
                "created_at": item.get("created_at"),
            })

        payload = {
            "repository": f"{owner}/{repo}",
            "state_filter": state,
            "total_returned": len(issues),
            "issues": issues,
        }
        return self._success_result(json.dumps(payload, indent=2))

    async def tool_search_repositories(self, args: Mapping[str, Any]) -> CallToolResult:
        """Search GitHub repositories by query."""
        query = args.get("query")
        if not query:
            return self._error_result("Missing required argument: 'query'")

        per_page = min(max(int(args.get("per_page", 10)), 1), 50)
        url = f"{self.base_url}/search/repositories"
        params = {"q": query, "per_page": per_page}
        data = await self._send_request("GET", url, params=params)

        items = []
        for repo in data.get("items", []):
            items.append({
                "full_name": repo.get("full_name"),
                "description": repo.get("description"),
                "stars": repo.get("stargazers_count"),
                "html_url": repo.get("html_url"),
            })

        payload = {
            "query": query,
            "total_count": data.get("total_count", 0),
            "results": items,
        }
        return self._success_result(json.dumps(payload, indent=2))

    # --- HTTP Helper ---

    async def _send_request(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Send HTTP request to GitHub API using shared pooled client."""
        headers = self._get_headers()
        client = self._get_client()
        response = await client.request(method, url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()

    def _success_result(self, text: str) -> CallToolResult:
        return CallToolResult(content=[TextContent(type="text", text=text)], is_error=False)

    def _error_result(self, message: str) -> CallToolResult:
        return CallToolResult(content=[TextContent(type="text", text=message)], is_error=True)


def create_github_server(token: str | None = None) -> Server:
    """Factory creating an MCP low-level Server for GitHub."""
    app = GitHubMCPServer(token=token)
    return app.server


async def main() -> None:
    """Run the GitHub MCP server over stdio."""
    app = GitHubMCPServer()
    try:
        async with stdio_server() as (read_stream, write_stream):
            init_options = app.server.create_initialization_options()
            await app.server.run(read_stream, write_stream, init_options)
    finally:
        await app.aclose()


if __name__ == "__main__":
    asyncio.run(main())
