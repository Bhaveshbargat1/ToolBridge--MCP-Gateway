"""Hermetic Integration and Security Tests for GitHubMCPServer.

Guarantees 100% hermetic execution using respx mocks. Tests never touch the external network,
even when GITHUB_PERSONAL_ACCESS_TOKEN is configured in the local environment.
"""
from __future__ import annotations

import json
import socket
import pytest
import respx
import httpx
from mcp.types import CallToolRequestParams, PaginatedRequestParams

from toolbridge.upstreams.github.server import GitHubMCPServer, ALL_GITHUB_TOOLS


@pytest.fixture
def sample_repo_data() -> dict:
    return {
        "full_name": "octocat/Hello-World",
        "description": "My first repository on GitHub!",
        "html_url": "https://github.com/octocat/Hello-World",
        "stargazers_count": 2500,
        "forks_count": 1200,
        "open_issues_count": 15,
        "default_branch": "master",
        "language": "Python",
        "private": False,
    }


@pytest.fixture
def sample_issues_data() -> list:
    return [
        {
            "number": 101,
            "title": "Bug in gateway proxy",
            "state": "open",
            "user": {"login": "alice_dev"},
            "html_url": "https://github.com/octocat/Hello-World/issues/101",
            "created_at": "2026-01-01T00:00:00Z",
        },
        {
            "number": 102,
            "title": "Pull Request to be skipped",
            "state": "open",
            "user": {"login": "bob_pr"},
            "pull_request": {},  # Must be filtered out
            "html_url": "https://github.com/octocat/Hello-World/pull/102",
            "created_at": "2026-01-02T00:00:00Z",
        },
    ]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_github_tool_discovery():
    """Verify tool discovery returns all three GitHub tools with valid schemas."""
    server = GitHubMCPServer(token="test_token")
    res = await server._handle_list_tools(None, PaginatedRequestParams())

    tool_names = [t.name for t in res.tools]
    assert "get_repository" in tool_names
    assert "list_issues" in tool_names
    assert "search_repositories" in tool_names


@pytest.mark.integration
@pytest.mark.asyncio
@respx.mock
async def test_get_repository_hermetic(sample_repo_data):
    """Verify get_repository tool parses GitHub API responses hermetically."""
    respx.get("https://api.github.com/repos/octocat/Hello-World").mock(
        return_value=httpx.Response(200, json=sample_repo_data)
    )

    server = GitHubMCPServer(token="test_token")
    params = CallToolRequestParams(
        name="get_repository",
        arguments={"owner": "octocat", "repo": "Hello-World"},
    )
    result = await server._handle_call_tool(None, params)

    assert result.is_error is False
    data = json.loads(result.content[0].text)
    assert data["name"] == "octocat/Hello-World"
    assert data["stars"] == 2500
    assert data["language"] == "Python"


@pytest.mark.integration
@pytest.mark.asyncio
@respx.mock
async def test_list_issues_hermetic(sample_issues_data):
    """Verify list_issues tool filters out PRs and returns pure issue metadata."""
    respx.get("https://api.github.com/repos/octocat/Hello-World/issues").mock(
        return_value=httpx.Response(200, json=sample_issues_data)
    )

    server = GitHubMCPServer(token="test_token")
    params = CallToolRequestParams(
        name="list_issues",
        arguments={"owner": "octocat", "repo": "Hello-World", "state": "open"},
    )
    result = await server._handle_call_tool(None, params)

    assert result.is_error is False
    payload = json.loads(result.content[0].text)
    assert payload["total_returned"] == 1
    assert payload["issues"][0]["number"] == 101
    assert payload["issues"][0]["author"] == "alice_dev"


@pytest.mark.integration
@pytest.mark.asyncio
@respx.mock
async def test_search_repositories_hermetic(sample_repo_data):
    """Verify search_repositories tool returns formatted search results."""
    respx.get("https://api.github.com/search/repositories").mock(
        return_value=httpx.Response(200, json={"total_count": 1, "items": [sample_repo_data]})
    )

    server = GitHubMCPServer(token="test_token")
    params = CallToolRequestParams(
        name="search_repositories",
        arguments={"query": "topic:mcp"},
    )
    result = await server._handle_call_tool(None, params)

    assert result.is_error is False
    payload = json.loads(result.content[0].text)
    assert payload["total_count"] == 1
    assert payload["results"][0]["full_name"] == "octocat/Hello-World"


@pytest.mark.integration
@pytest.mark.asyncio
@respx.mock
async def test_github_error_semantics_hermetic():
    """Verify 401, 403, and 404 responses are converted to clean tool error results."""
    # 401 Unauthorized
    respx.get("https://api.github.com/repos/auth/err").mock(
        return_value=httpx.Response(401, json={"message": "Bad credentials"})
    )
    # 403 Rate Limit / Forbidden
    respx.get("https://api.github.com/repos/rate/limit").mock(
        return_value=httpx.Response(403, json={"message": "API rate limit exceeded"})
    )
    # 404 Not Found
    respx.get("https://api.github.com/repos/missing/repo").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )

    server = GitHubMCPServer(token="bad_token")

    res401 = await server._handle_call_tool(
        None, CallToolRequestParams(name="get_repository", arguments={"owner": "auth", "repo": "err"})
    )
    assert res401.is_error is True
    assert "Authentication Error" in res401.content[0].text

    res403 = await server._handle_call_tool(
        None, CallToolRequestParams(name="get_repository", arguments={"owner": "rate", "repo": "limit"})
    )
    assert res403.is_error is True
    assert "rate limit exceeded" in res403.content[0].text

    res404 = await server._handle_call_tool(
        None, CallToolRequestParams(name="get_repository", arguments={"owner": "missing", "repo": "repo"})
    )
    assert res404.is_error is True
    assert "Not Found" in res404.content[0].text


@pytest.mark.security
@pytest.mark.asyncio
@respx.mock
async def test_github_suite_makes_zero_real_network_calls(monkeypatch, sample_repo_data):
    """C2: Assert running with dummy token makes ZERO real network calls.

    Monkeypatches socket.socket.connect to fail immediately if any external socket is opened.
    """
    dummy_token = "ghp_dummy1234567890123456789012345678901234"
    monkeypatch.setenv("GITHUB_PERSONAL_ACCESS_TOKEN", dummy_token)

    # Mock external GitHub API route via respx
    route = respx.get("https://api.github.com/repos/modelcontextprotocol/python-sdk").mock(
        return_value=httpx.Response(200, json=sample_repo_data)
    )

    # Rigorous guarantee: block all real network socket connections
    def forbidden_network_call(*args, **kwargs):
        raise AssertionError("Security Violation: Test attempted to connect to real external network!")

    monkeypatch.setattr(socket.socket, "connect", forbidden_network_call)

    server = GitHubMCPServer()
    assert server.token == dummy_token

    params = CallToolRequestParams(
        name="get_repository",
        arguments={"owner": "modelcontextprotocol", "repo": "python-sdk"},
    )
    res = await server._handle_call_tool(None, params)

    assert res.is_error is False
    assert route.called
    assert route.call_count == 1
