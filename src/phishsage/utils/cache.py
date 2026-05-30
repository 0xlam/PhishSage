from __future__ import annotations
from pathlib import Path
from phishsage.config.loader import CACHE_DIR

try:
    import diskcache
except ImportError as exc:
    raise ImportError(
        "Caching requires additional dependencies. "
        "Install with: pip install phishsage[cache]"
    ) from exc


def get_cache(cache_dir: str | None = None) -> diskcache.Cache:
    path = Path(cache_dir) if cache_dir else CACHE_DIR
    path.mkdir(parents=True, exist_ok=True)
    return diskcache.Cache(str(path))
