import asyncio
import hashlib
from typing import Dict, Any, Optional


class AttachmentHeuristics:

    VT_ZERO_FIELDS = {
        "timeout",
        "confirmed-timeout",
        "failure",
        "type-unsupported",
        "resource",
        "error",
    }

    def __init__(self, processor, vt_client=None, yara_engine=None, yara_verbose=False):
        self.processor = processor
        self.vt_client = vt_client
        self.yara_engine = yara_engine
        self.yara_verbose = yara_verbose

        self.attachments = None

    # -------------------------
    # attachment loading
    # -------------------------

    def _ensure_attachments(self) -> Dict[str, Any]:
        if self.attachments is None:
            self.attachments = self.processor.force_parse() or {}
        return self.attachments

    # -------------------------
    # response helper
    # -------------------------

    def _wrap(self, items: Dict[str, Any], errors=None) -> Dict[str, Any]:
        errors = errors or []

        return {
            "attachments": items,
            "summary": {
                "total": len(items),
                "scanned": len(items),
                "errors": errors,
            },
        }

    # -------------------------
    # VirusTotal Scan
    # -------------------------

    async def vt_scan(self) -> dict:
        attachments = self._ensure_attachments()

        if not attachments:
            return self._wrap({}, errors=["no_attachments"])

        results = {}
        errors = []

        
        if not self.vt_client:
            for fname, meta in attachments.items():
                results[fname] = self._vt_unavailable(meta)
            return self._wrap(results, errors=["missing_vt_service"])

        fnames = list(attachments.keys())
        tasks = []

        for fname in fnames:
            meta = attachments[fname]
            sha256 = hashlib.sha256(meta["file_bytes"]).hexdigest()
            tasks.append(self.vt_client(sha256))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for fname, vt in zip(fnames, responses):
            meta = attachments[fname]
            sha256 = hashlib.sha256(meta["file_bytes"]).hexdigest()

            if isinstance(vt, Exception):
                results[fname] = {
                    "sha256": sha256,
                    "virustotal": {
                        "status": "exception",
                        "reason": "vt_exception",
                        "stats": {},
                        "error": str(vt),
                    },
                }
                continue

            stats = {}
            if vt.status == "ok" and vt.stats:
                raw = vt.stats.__dict__
                stats = {
                    k: v for k, v in raw.items()
                    if k not in self.VT_ZERO_FIELDS
                }

            results[fname] = {
                "sha256": sha256,
                "virustotal": {
                    "status": vt.status,
                    "reason": getattr(vt, "error", None),
                    "stats": {
                        "last_analysis_stats": stats,
                        "last_analysis_date": getattr(vt, "last_analysis_date", None),
                        "first_submission_date": getattr(vt, "first_submission_date", None),
                    },
                },
            }

        return self._wrap(results)

    def _vt_unavailable(self, meta):
        return {
            "sha256": hashlib.sha256(meta["file_bytes"]).hexdigest(),
            "virustotal": {
                "status": "unavailable",
                "reason": "missing_vt_service",
                "stats": {},
            },
        }

    # -------------------------
    # YARA Scan
    # -------------------------

    def yara_scan(self, verbose: Optional[bool] = None) -> dict:
        verbose = self.yara_verbose if verbose is None else verbose
        attachments = self._ensure_attachments()

        if not attachments:
            return self._wrap({}, errors=["no_attachments"])

        results = {}
        errors = []

        
        if self.yara_engine is None:
            for fname in attachments:
                results[fname] = {
                    "flag": False,
                    "matches": [],
                    "error": "YARA engine not provided",
                }
            return self._wrap(results, errors=["missing_yara_engine"])

        for fname, meta in attachments.items():
            file_bytes = meta.get("file_bytes")

            if not file_bytes:
                results[fname] = {
                    "flag": False,
                    "matches": [],
                    "error": "No file bytes",
                }
                continue

            try:
                matches = self.yara_engine.scan(data=file_bytes)

                formatted = []
                for match in matches:
                    matched_flag = bool(match.strings)

                    match_dict = {
                        "flag": matched_flag,
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "rule_meta": match.meta or {},
                    }

                    if verbose and matched_flag:
                        strings = []
                        for s in match.strings:
                            for inst in s.instances:
                                strings.append({
                                    "name": s.identifier,
                                    "offset": hex(inst.offset),
                                    "data": inst.matched_data.hex(),
                                })

                        match_dict["strings"] = strings

                    formatted.append(match_dict)

                results[fname] = {
                    "flag": any(m["flag"] for m in formatted),
                    "matches": formatted,
                }

            except RuntimeError as e:
                results[fname] = {
                    "flag": False,
                    "matches": [],
                    "error": f"YARA runtime error: {e}",
                }

            except Exception as e:
                results[fname] = {
                    "flag": False,
                    "matches": [],
                    "error": f"Unexpected YARA error: {e}",
                }

        return self._wrap(results)