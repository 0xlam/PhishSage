from pathlib import Path

try:
    import diskcache
except ImportError as exc:
    raise ImportError(
        "Caching requires additional dependencies. "
        "Install with: pip install phishsage[cache]"
    ) from exc


def get_cache(cache_dir: str | None = None, config=None) -> diskcache.Cache:
    if cache_dir:
        path = Path(cache_dir).expanduser()
    elif config is not None:
        path = config.cache_dir
    else:
        path = Path("~/.cache/phishsage").expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return diskcache.Cache(str(path))
