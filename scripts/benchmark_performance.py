"""ToolBridge Enterprise MCP Gateway - Performance Benchmarking Suite.

Measures:
1. Rate Limiter Throughput (Sliding Window deque O(1))
2. Secret Sanitizer Throughput (Fast-path heuristic vs full regex)
3. Schema Validation & Dispatch Caching
4. Resilient PostgreSQL Fallback Latency (Eliminated 250ms TCP pre-flight)
5. Filesystem Sandboxed I/O Concurrency (asyncio.to_thread worker pool)
6. SQLite Audit Logging Throughput (Cached sessionmaker & zero-SELECT commit)
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import time
from typing import List
import numpy as np

# Ensure environment variables for secure test run
os.environ["TOOLBRIDGE_ADMIN_KEY"] = os.environ.get("TOOLBRIDGE_ADMIN_KEY", "tb_admin_perf_test_key_0001")
os.environ["TOOLBRIDGE_OPERATOR_KEY"] = os.environ.get("TOOLBRIDGE_OPERATOR_KEY", "tb_oper_perf_test_key_0002")
os.environ["TOOLBRIDGE_READONLY_KEY"] = os.environ.get("TOOLBRIDGE_READONLY_KEY", "tb_read_perf_test_key_0003")

from toolbridge.security.rate_limiter import SlidingWindowRateLimiter
from toolbridge.security.sanitizer import SecretSanitizer
from toolbridge.upstreams.postgres.backend import ResilientPostgresBackend
from toolbridge.db.session import init_db, get_session
from toolbridge.security.audit_service import AuditService
from toolbridge.upstreams.filesystem.server import FilesystemMCPServer
import jsonschema


def calc_stats(latencies_ms: List[float]) -> dict:
    arr = np.array(latencies_ms)
    return {
        "count": len(arr),
        "mean_ms": float(np.mean(arr)),
        "p50_ms": float(np.percentile(arr, 50)),
        "p95_ms": float(np.percentile(arr, 95)),
        "p99_ms": float(np.percentile(arr, 99)),
        "min_ms": float(np.min(arr)),
        "max_ms": float(np.max(arr)),
        "throughput_ops_sec": float(len(arr) / (np.sum(arr) / 1000.0)) if np.sum(arr) > 0 else 0.0,
    }


def print_stats(title: str, stats: dict) -> None:
    print(f"\n{'=' * 65}")
    print(f" {title}")
    print(f"{'=' * 65}")
    print(f"  Total Operations : {stats['count']:,}")
    print(f"  Throughput       : {stats['throughput_ops_sec']:,.1f} ops/sec")
    print(f"  Mean Latency     : {stats['mean_ms']:.4f} ms")
    print(f"  P50 Latency      : {stats['p50_ms']:.4f} ms")
    print(f"  P95 Latency      : {stats['p95_ms']:.4f} ms")
    print(f"  P99 Latency      : {stats['p99_ms']:.4f} ms")
    print(f"  Min / Max        : {stats['min_ms']:.4f} ms / {stats['max_ms']:.4f} ms")


async def benchmark_rate_limiter() -> None:
    limiter = SlidingWindowRateLimiter(max_requests_per_minute=100_000)
    latencies = []
    iterations = 10_000
    for i in range(iterations):
        caller = f"caller_{i % 50}"
        t0 = time.perf_counter()
        await limiter.check_rate_limit(caller)
        latencies.append((time.perf_counter() - t0) * 1000)

    stats = calc_stats(latencies)
    print_stats("1. Rate Limiter (O(1) Deque Sliding Window)", stats)


async def benchmark_sanitizer() -> None:
    # 5,000 benign requests + 5,000 secret-containing requests
    benign_text = "SELECT id, name, email FROM users WHERE department = 'Engineering' LIMIT 50"
    sensitive_text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sk-proj-abc1234567890def postgresql://user:pass123@localhost:5432/db"

    benign_latencies = []
    sensitive_latencies = []

    for _ in range(5_000):
        t0 = time.perf_counter()
        SecretSanitizer.sanitize(benign_text)
        benign_latencies.append((time.perf_counter() - t0) * 1000)

    for _ in range(5_000):
        t0 = time.perf_counter()
        SecretSanitizer.sanitize(sensitive_text)
        sensitive_latencies.append((time.perf_counter() - t0) * 1000)

    stats_benign = calc_stats(benign_latencies)
    print_stats("2A. Secret Sanitizer - Benign Strings (Fast-Path Filter)", stats_benign)

    stats_sensitive = calc_stats(sensitive_latencies)
    print_stats("2B. Secret Sanitizer - Sensitive Strings (Full Regex Redaction)", stats_sensitive)


async def benchmark_schema_validator() -> None:
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 1},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
            "parameters": {"type": "object"},
        },
        "required": ["query"],
    }
    payload = {"query": "SELECT * FROM orders WHERE status = 'pending'", "limit": 100, "parameters": {}}

    # Precompiled validator
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    compiled_validator = validator_cls(schema)

    cached_latencies = []
    for _ in range(5_000):
        t0 = time.perf_counter()
        compiled_validator.validate(payload)
        cached_latencies.append((time.perf_counter() - t0) * 1000)

    uncached_latencies = []
    for _ in range(5_000):
        t0 = time.perf_counter()
        jsonschema.validate(instance=payload, schema=schema)
        uncached_latencies.append((time.perf_counter() - t0) * 1000)

    print_stats("3A. JSON Schema Validation - Pre-compiled & Cached Validator", calc_stats(cached_latencies))
    print_stats("3B. JSON Schema Validation - Uncached Dynamic jsonschema.validate()", calc_stats(uncached_latencies))


async def benchmark_postgres_resilient_fallback() -> None:
    # Test query execution latency in fallback mode (no PostgreSQL server on port 5432)
    backend = ResilientPostgresBackend()
    try:
        # Pre-connect (first attempt triggers timeout and falls back to SQLite)
        t_init0 = time.perf_counter()
        await backend.connect()
        init_time_ms = (time.perf_counter() - t_init0) * 1000

        print(f"\n[Postgres Backend] Initial fallback transition: {init_time_ms:.2f}ms (is_fallback={backend.is_fallback})")

        latencies = []
        for _ in range(100):
            t0 = time.perf_counter()
            res = await backend.execute_query("SELECT 1 as num, 'hello' as greeting;")
            latencies.append((time.perf_counter() - t0) * 1000)
            assert len(res) == 1

        stats = calc_stats(latencies)
        print_stats("4. Resilient PostgreSQL Query Latency (Fallback Guarded)", stats)
    finally:
        await backend.disconnect()


async def benchmark_filesystem_concurrency() -> None:
    temp_dir = tempfile.mkdtemp(prefix="tb_bench_fs_")
    try:
        fs = FilesystemMCPServer(sandbox_root=temp_dir)

        # Create 100 files concurrently using worker threads
        async def create_file(idx: int) -> float:
            path = f"test_file_{idx}.txt"
            data = f"Benchmark content payload for file index {idx}\n" * 50
            t0 = time.perf_counter()
            res = await fs.tool_write_file({"path": path, "content": data})
            assert not res.is_error
            return (time.perf_counter() - t0) * 1000

        async def read_file(idx: int) -> float:
            path = f"test_file_{idx}.txt"
            t0 = time.perf_counter()
            res = await fs.tool_read_file({"path": path})
            assert not res.is_error
            return (time.perf_counter() - t0) * 1000

        write_latencies = await asyncio.gather(*(create_file(i) for i in range(100)))
        print_stats("5A. Sandboxed Filesystem - Concurrent Async Writes (to_thread)", calc_stats(list(write_latencies)))

        read_latencies = await asyncio.gather(*(read_file(i) for i in range(100)))
        print_stats("5B. Sandboxed Filesystem - Concurrent Async Reads (to_thread)", calc_stats(list(read_latencies)))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


async def benchmark_audit_service() -> None:
    await init_db()
    latencies = []
    # Test batch of 200 audit records
    for i in range(200):
        t0 = time.perf_counter()
        async with get_session() as session:
            await AuditService.record_event(
                session=session,
                caller_id=f"bench_user_{i % 5}",
                caller_role="operator",
                tool_name="postgres__query",
                server_id="postgres",
                arguments={"query": "SELECT * FROM metrics", "limit": 10},
                status="SUCCESS",
                duration_ms=1.45,
                response_summary="Result with 10 rows",
            )
        latencies.append((time.perf_counter() - t0) * 1000)

    print_stats("6. SQLite Audit Logging (Cached sessionmaker + Zero-Refresh)", calc_stats(latencies))


async def main() -> None:
    print("\n" + "#" * 65)
    print(" TOOLBRIDGE GATEWAY - PERFORMANCE BENCHMARK SUITE")
    print("#" * 65)
    await benchmark_rate_limiter()
    await benchmark_sanitizer()
    await benchmark_schema_validator()
    await benchmark_postgres_resilient_fallback()
    await benchmark_filesystem_concurrency()
    await benchmark_audit_service()
    print("\n" + "#" * 65)
    print(" BENCHMARK COMPLETE - ALL SUBSYSTEMS VERIFIED")
    print("#" * 65 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
