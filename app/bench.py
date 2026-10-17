"""
Benchmark script for Nagarkot Access Control Service.
Standard library only: sqlite3, time, statistics, json, ctypes, platform, os.
Measures real performance on 200,000 jobs and 500 users.
Target: list/count queries on 200,000 jobs under ~50 ms in <100 MB RAM.
"""

import time
import json
import sqlite3
import statistics
import platform
import os
import sys
from pathlib import Path
from typing import Dict, Any, List

from app.db import init_db, get_connection, DB_PATH
from app.predicate import PredicateCompiler
from app.engine import DecisionEngine
from app.seed import seed_scale

def get_process_memory_mb() -> float:
    """
    Get current process Resident Set Size (RSS) in MB using ctypes on Windows,
    or resource module on POSIX. Standard library only.
    """
    if platform.system() == "Windows":
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            psapi = ctypes.windll.psapi
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(pmc)
            handle = wintypes.HANDLE(ctypes.windll.kernel32.GetCurrentProcess())
            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
                return pmc.WorkingSetSize / (1024 * 1024)
        except Exception:
            pass
    else:
        try:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF)
            # macOS returns bytes, Linux returns kilobytes
            multiplier = 1 / (1024 * 1024) if sys.platform == "darwin" else 1 / 1024
            return usage.ru_maxrss * multiplier
        except Exception:
            pass

    return 0.0

def run_benchmarks(scale_db_path: Path = DB_PATH):
    print("=" * 75)
    print("NAGARKOT ACCESS CONTROL SERVICE - BENCHMARK SUITE")
    print("=" * 75)

    conn = get_connection(scale_db_path)
    cur = conn.execute("SELECT COUNT(*) as job_count FROM jobs")
    job_count = cur.fetchone()["job_count"]
    cur = conn.execute("SELECT COUNT(*) as user_count FROM users")
    user_count = cur.fetchone()["user_count"]

    if job_count < 200_000:
        print(f"Current DB has {job_count:,} jobs. Generating scale database (200,000 jobs)...")
        conn.close()
        seed_scale(scale_db_path)
        conn = get_connection(scale_db_path)
        job_count = conn.execute("SELECT COUNT(*) as job_count FROM jobs").fetchone()["job_count"]
        user_count = conn.execute("SELECT COUNT(*) as user_count FROM users").fetchone()["user_count"]

    # Gather System Info
    cpu_info = platform.processor() or "x86_64"
    py_ver = platform.python_version()
    os_info = f"{platform.system()} {platform.release()}"
    print(f"System:      {os_info} | Python {py_ver}")
    print(f"Processor:   {cpu_info}")
    print(f"Scale Stats: {job_count:,} jobs, {user_count:,} users in SQLite WAL mode")
    print(f"Database:    {scale_db_path} ({scale_db_path.stat().st_size / (1024 * 1024):.2f} MB)")
    print("-" * 75)

    engine = DecisionEngine(conn)
    role_map = {}
    for r in conn.execute("SELECT name, permissions FROM roles WHERE is_active = 1").fetchall():
        role_map[r["name"]] = json.loads(r["permissions"])

    test_users = ["u_asha", "u_ravi", "u_suresh", "u_deepa", "u_manoj"]
    iterations = 50

    results = {}

    # 1. Measure "Jobs waiting for me" COUNT queries
    print("\n[Benchmark 1] 'Jobs waiting for me' COUNT Query (50 iterations per user)")
    count_timings = []
    for uid in test_users:
        user_grants = engine._fetch_active_grants(uid) + engine._fetch_active_delegations(uid)
        _, sql_where, params = PredicateCompiler.compile_waiting_for_user(uid, user_grants, role_map)
        query = f"SELECT COUNT(*) as total FROM jobs WHERE {sql_where}"

        user_times = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            cnt = conn.execute(query, params).fetchone()["total"]
            t1 = time.perf_counter()
            user_times.append((t1 - t0) * 1000)  # ms

        mean_ms = statistics.mean(user_times)
        median_ms = statistics.median(user_times)
        p95_ms = sorted(user_times)[int(len(user_times) * 0.95)]
        min_ms = min(user_times)
        count_timings.extend(user_times)
        print(f"  User {uid:8s}: count={cnt:,} jobs | Mean: {mean_ms:6.2f} ms | Median: {median_ms:6.2f} ms | p95: {p95_ms:6.2f} ms | Min: {min_ms:6.2f} ms")

    results["waiting_count"] = {
        "mean_ms": round(statistics.mean(count_timings), 2),
        "median_ms": round(statistics.median(count_timings), 2),
        "p95_ms": round(sorted(count_timings)[int(len(count_timings) * 0.95)], 2),
        "min_ms": round(min(count_timings), 2),
    }

    # 2. Measure "Jobs waiting for me" LIST queries (Limit 50)
    print("\n[Benchmark 2] 'Jobs waiting for me' LIST Query (Limit 50 rows, 50 iterations per user)")
    list_timings = []
    for uid in test_users:
        user_grants = engine._fetch_active_grants(uid) + engine._fetch_active_delegations(uid)
        _, sql_where, params = PredicateCompiler.compile_waiting_for_user(uid, user_grants, role_map)
        query = f"SELECT id, client_id, branch, direction, mode, stage, prepared_by FROM jobs WHERE {sql_where} ORDER BY id ASC LIMIT 50"

        user_times = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            rows = conn.execute(query, params).fetchall()
            t1 = time.perf_counter()
            user_times.append((t1 - t0) * 1000)

        mean_ms = statistics.mean(user_times)
        median_ms = statistics.median(user_times)
        p95_ms = sorted(user_times)[int(len(user_times) * 0.95)]
        min_ms = min(user_times)
        list_timings.extend(user_times)
        print(f"  User {uid:8s}: fetched={len(rows)} rows | Mean: {mean_ms:6.2f} ms | Median: {median_ms:6.2f} ms | p95: {p95_ms:6.2f} ms | Min: {min_ms:6.2f} ms")

    results["waiting_list"] = {
        "mean_ms": round(statistics.mean(list_timings), 2),
        "median_ms": round(statistics.median(list_timings), 2),
        "p95_ms": round(sorted(list_timings)[int(len(list_timings) * 0.95)], 2),
        "min_ms": round(min(list_timings), 2),
    }

    # 3. Keyset Pagination on 200,000 jobs (deep offset simulation)
    print("\n[Benchmark 3] Keyset Pagination on 200,000 Jobs (LIMIT 50, after deep offsets)")
    keyset_timings = []
    test_offsets = ["JOB_0010000", "JOB_0050000", "JOB_0100000", "JOB_0150000", "JOB_0190000"]
    for offset_id in test_offsets:
        query = "SELECT id, client_id, branch, direction, mode, stage FROM jobs WHERE id > :after ORDER BY id ASC LIMIT 50"
        offset_times = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            rows = conn.execute(query, {"after": offset_id}).fetchall()
            t1 = time.perf_counter()
            offset_times.append((t1 - t0) * 1000)
        mean_ms = statistics.mean(offset_times)
        median_ms = statistics.median(offset_times)
        p95_ms = sorted(offset_times)[int(len(offset_times) * 0.95)]
        keyset_timings.extend(offset_times)
        print(f"  After {offset_id}: Mean: {mean_ms:6.2f} ms | Median: {median_ms:6.2f} ms | p95: {p95_ms:6.2f} ms")

    results["keyset_pagination"] = {
        "mean_ms": round(statistics.mean(keyset_timings), 2),
        "median_ms": round(statistics.median(keyset_timings), 2),
        "p95_ms": round(sorted(keyset_timings)[int(len(keyset_timings) * 0.95)], 2),
    }

    # 4. Measure Single Authorization Decision + HMAC Receipt Signing
    print("\n[Benchmark 4] Single Job Authorization Decision + HMAC Signature (1,000 iterations)")
    auth_times = []
    for _ in range(1000):
        t0 = time.perf_counter()
        rec = engine.authorize(actor_id="u_asha", action="prepare", job_id="JOB_0000001")
        t1 = time.perf_counter()
        auth_times.append((t1 - t0) * 1000)

    results["single_auth"] = {
        "mean_ms": round(statistics.mean(auth_times), 3),
        "median_ms": round(statistics.median(auth_times), 3),
        "p95_ms": round(sorted(auth_times)[int(len(auth_times) * 0.95)], 3),
        "throughput_ops_per_sec": round(1000 / statistics.mean(auth_times), 1),
    }
    print(f"  Authorization Latency: Mean: {results['single_auth']['mean_ms']} ms | Median: {results['single_auth']['median_ms']} ms | p95: {results['single_auth']['p95_ms']} ms")
    print(f"  Authorization Throughput: {results['single_auth']['throughput_ops_per_sec']:,} checks/second")

    # 5. Measure Process Memory
    mem_mb = get_process_memory_mb()
    results["memory_rss_mb"] = round(mem_mb, 2)
    print(f"\n[Memory Footprint] Process Working Set RSS: {mem_mb:.2f} MB (Target: < 100 MB)")

    conn.close()
    print("\n" + "=" * 75)
    print("BENCHMARK SUMMARY REPORT")
    print("=" * 75)
    print(f"Dataset:                  200,000 jobs, 500 users")
    print(f"Waiting Count Mean:       {results['waiting_count']['mean_ms']} ms (Target: < 50 ms)")
    print(f"Waiting List Mean:        {results['waiting_list']['mean_ms']} ms (Target: < 50 ms)")
    print(f"Keyset Pagination Mean:   {results['keyset_pagination']['mean_ms']} ms (Target: < 50 ms)")
    print(f"Single Auth Latency Mean: {results['single_auth']['mean_ms']} ms ({results['single_auth']['throughput_ops_per_sec']:,} ops/s)")
    print(f"Process RAM (RSS):        {results['memory_rss_mb']} MB (Constraint: < 100 MB)")
    print("=" * 75)

    return results

if __name__ == "__main__":
    run_benchmarks()
