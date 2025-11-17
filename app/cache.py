import threading
from typing import Any, Optional
from app.config import CACHE_DIR

try:
    import diskcache
    _cache = diskcache.Cache(CACHE_DIR)
    _use_diskcache = True
except ImportError:  # fallback
    _cache = {}
    _use_diskcache = False

_lock = threading.Lock()


def get_cache(key: str) -> Optional[Any]:
    with _lock:
        return _cache.get(key)


def set_cache(key: str, value: Any, expire: int = 300) -> None:
    with _lock:
        if _use_diskcache:
            _cache.set(key, value, expire=expire)
        else:
            _cache[key] = value
