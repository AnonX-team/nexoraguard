"""
Resource Optimizer
Keeps NexoraGuard under 50MB RAM and <2% CPU.
Techniques:
  - Cached results with TTL (avoid repeated expensive calls)
  - Adaptive scan intervals (slow down when system is idle)
  - Memory cleanup (gc.collect on schedule)
  - CPU throttling (sleep between operations)
  - Lightweight metric collection
"""
import gc
import os
import time
import logging
import threading
import psutil
from functools import wraps
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ── Cache with TTL ────────────────────────────────────────────────────────────
_cache: dict = {}
_cache_lock = threading.Lock()


def cached(ttl_seconds: int):
    """Decorator: cache function result for ttl_seconds."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = f"{func.__name__}:{args}:{kwargs}"
            with _cache_lock:
                if key in _cache:
                    result, expires_at = _cache[key]
                    if datetime.now() < expires_at:
                        return result

            result = func(*args, **kwargs)

            with _cache_lock:
                _cache[key] = (result, datetime.now() + timedelta(seconds=ttl_seconds))

            return result
        return wrapper
    return decorator


def clear_cache():
    """Clear all cached results."""
    with _cache_lock:
        _cache.clear()


# ── Memory Usage ──────────────────────────────────────────────────────────────
def get_self_memory_mb() -> float:
    """Get current process memory usage in MB."""
    try:
        proc = psutil.Process(os.getpid())
        return round(proc.memory_info().rss / (1024 * 1024), 2)
    except Exception:
        return 0.0


def get_self_cpu_percent() -> float:
    """Get current process CPU usage."""
    try:
        proc = psutil.Process(os.getpid())
        return round(proc.cpu_percent(interval=0.1), 2)
    except Exception:
        return 0.0


def force_cleanup():
    """Force garbage collection and trim cache."""
    # Remove expired cache entries
    now = datetime.now()
    with _cache_lock:
        expired = [k for k, (_, exp) in _cache.items() if now >= exp]
        for k in expired:
            del _cache[k]

    # Python garbage collection
    collected = gc.collect()
    logger.debug(f"GC collected {collected} objects | Cache trimmed {len(expired)} entries")
    return {"gc_collected": collected, "cache_expired_removed": len(expired)}


# ── Adaptive Scan Interval ────────────────────────────────────────────────────
class AdaptiveScanner:
    """
    Automatically adjusts scan frequency based on:
    - System CPU load (slow down if CPU > 80%)
    - Risk level (speed up if threats detected)
    - NexoraGuard own resource usage
    """
    MIN_INTERVAL = 10    # fastest scan: every 10s
    MAX_INTERVAL = 60    # slowest scan: every 60s
    DEFAULT      = 15

    def __init__(self):
        self.current_interval = self.DEFAULT
        self.last_risk_score  = 0

    def get_next_interval(self, risk_score: int = 0) -> int:
        system_cpu = psutil.cpu_percent(interval=0.2)
        self_mem   = get_self_memory_mb()
        self_cpu   = get_self_cpu_percent()

        # If threat detected — scan faster
        if risk_score >= 70:
            self.current_interval = self.MIN_INTERVAL
            logger.debug(f"High risk ({risk_score}) — fast scan every {self.current_interval}s")

        # If system CPU is high or we're using too much memory — slow down
        elif system_cpu > 80 or self_mem > 45:
            self.current_interval = min(self.current_interval + 5, self.MAX_INTERVAL)
            logger.debug(f"System load high (CPU:{system_cpu}% Mem:{self_mem}MB) — slowing to {self.current_interval}s")

        # Normal — gradually return to default
        elif risk_score < 20:
            self.current_interval = max(self.current_interval - 2, self.DEFAULT)

        self.last_risk_score = risk_score
        return self.current_interval


# ── Throttled Execution ───────────────────────────────────────────────────────
def throttled_sleep(seconds: float, check_interval: float = 0.5):
    """
    Sleep in small chunks so we can be interrupted.
    Better than time.sleep(60) for a service.
    """
    elapsed = 0.0
    while elapsed < seconds:
        time.sleep(min(check_interval, seconds - elapsed))
        elapsed += check_interval


# ── Resource Guard ────────────────────────────────────────────────────────────
class ResourceGuard:
    """
    Background thread that monitors NexoraGuard's own resource usage.
    Triggers cleanup if limits are exceeded.
    """
    RAM_LIMIT_MB  = 50
    CPU_LIMIT_PCT = 2.0
    CHECK_EVERY   = 30   # seconds

    def __init__(self):
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._running = False

    def start(self):
        self._running = True
        self._thread.start()
        logger.info("ResourceGuard started")

    def stop(self):
        self._running = False

    def _monitor(self):
        while self._running:
            mem = get_self_memory_mb()
            cpu = get_self_cpu_percent()

            if mem > self.RAM_LIMIT_MB:
                logger.warning(f"RAM limit exceeded: {mem}MB > {self.RAM_LIMIT_MB}MB — running cleanup")
                force_cleanup()
                # Clear psutil process cache
                try:
                    if hasattr(psutil, '_cache'):
                        psutil._cache.clear()
                except Exception:
                    pass

            if cpu > self.CPU_LIMIT_PCT * 3:  # 3x limit triggers warning
                logger.warning(f"CPU spike: {cpu}% — consider increasing scan interval")

            time.sleep(self.CHECK_EVERY)


# ── Stats Reporter ────────────────────────────────────────────────────────────
def get_resource_stats() -> dict:
    """Get NexoraGuard's own resource usage stats."""
    mem = get_self_memory_mb()
    cpu = get_self_cpu_percent()
    return {
        "memory_mb": mem,
        "cpu_percent": cpu,
        "memory_limit_mb": ResourceGuard.RAM_LIMIT_MB,
        "cpu_limit_pct": ResourceGuard.CPU_LIMIT_PCT,
        "memory_ok": mem <= ResourceGuard.RAM_LIMIT_MB,
        "cpu_ok": cpu <= ResourceGuard.CPU_LIMIT_PCT * 3,
        "cache_entries": len(_cache),
        "timestamp": datetime.now().isoformat()
    }


# Global instances
adaptive_scanner = AdaptiveScanner()
resource_guard   = ResourceGuard()
