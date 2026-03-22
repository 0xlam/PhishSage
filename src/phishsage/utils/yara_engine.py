import os
import threading
import logging
from pathlib import Path
from typing import List, Union, Iterable, Dict, Any, Optional

import yara


class YaraEngine:

    VALID_EXTENSIONS = {".yar", ".yara"}

    def __init__(
        self,
        rules_path: Union[str, Path, Iterable[Union[str, Path]]],
        *,
        fail_soft: bool = False,
        logger: Optional[logging.Logger] = None,
    ):
        self._lock = threading.RLock()
        self._rules: Optional[yara.Rules] = None
        self._rule_paths: List[str] = []
        self.fail_soft = fail_soft
        self.log = logger or logging.getLogger(__name__)

        self._initialize(rules_path)

    def scan(self, data: bytes, timeout: int = 60) -> List[yara.Match]:
        """
        Scan raw bytes and return raw YARA match objects.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("scan() requires bytes-like object")

        with self._lock:
            rules = self._rules

        if rules is None:
            raise RuntimeError("YARA rules not loaded")

        return rules.match(data=data, timeout=timeout)

    def reload(self) -> None:
        """
        Recompile rules from original paths.
        """
        with self._lock:
            self.log.info("Reloading YARA rules...")
            self._compile_rules()
            self.log.info("Reload complete.")

    # ============================================================
    # INITIALIZATION
    # ============================================================

    def _initialize(self, rules_path) -> None:
        paths = self._resolve_rule_paths(rules_path)

        if not paths:
            raise ValueError("No valid YARA rule files provided.")

        self._rule_paths = paths
        self._compile_rules()

    def _resolve_rule_paths(
        self,
        rules_path: Union[str, Path, Iterable[Union[str, Path]]],
    ) -> List[str]:

        if isinstance(rules_path, (str, Path)):
            rules_path = [rules_path]

        if not isinstance(rules_path, Iterable):
            raise TypeError("rules_path must be path or iterable of paths")

        resolved: List[str] = []

        for item in rules_path:
            p = Path(item)

            if p.is_dir():
                for file in p.rglob("*"):
                    if (
                        file.is_file()
                        and file.suffix.lower() in self.VALID_EXTENSIONS
                        and not file.name.startswith(".")
                        and not file.name.endswith("~")
                    ):
                        resolved.append(str(file))

            elif p.is_file():
                resolved.append(str(p))

            else:
                raise FileNotFoundError(f"Invalid rule path: {item}")

        return sorted(set(resolved))

    # ============================================================
    # COMPILATION
    # ============================================================

    def _compile_rules(self) -> None:

        filepaths: Dict[str, str] = {}

        for i, path in enumerate(self._rule_paths, 1):
            if not os.path.isfile(path):
                msg = f"Rule file missing: {path}"
                if self.fail_soft:
                    self.log.warning(msg)
                    continue
                raise FileNotFoundError(msg)

            namespace = Path(path).stem.replace(".", "_") or f"rule_{i}"
            filepaths[namespace] = path

        if not filepaths:
            raise RuntimeError("No rule files available for compilation.")

        try:
            compiled = yara.compile(filepaths=filepaths)

        except yara.SyntaxError as e:
            if self.fail_soft:
                self.log.error("YARA syntax error: %s", e)
                return
            raise ValueError(f"YARA syntax error: {e}") from e

        except Exception as e:
            raise RuntimeError(f"Failed compiling rules: {e}") from e

        self._rules = compiled
