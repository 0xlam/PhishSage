import asyncio
from typing import Dict, Any, List, Optional
import hashlib


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
        """
        Attachments heuristics engine.

        :param processor: AttachmentProcessor instance
        :param vt_client: Function to query VirusTotal
        :param yara_engine: YARA engine instance
        :param yara_verbose: Show detailed YARA matches
        """
        self.processor = processor
        self.vt_client = vt_client
        self.yara_engine = yara_engine
        self.yara_verbose = yara_verbose

        self.attachments = None

    def _ensure_attachments(self):
        if self.attachments is None:
            self.attachments = self.processor.force_parse()
        return self.attachments

    # -----------------------------
    # VirusTotal Scan
    # -----------------------------

    async def vt_scan(self) -> Dict[str, Dict[str, Any]]:
        """
        Scan attachments on VirusTotal, return normalized results
        """
        attachments = self._ensure_attachments()
        if not attachments:
            return {}

        fnames = []
        sha256_list = []
        tasks = []

        for fname, meta in attachments.items():
            file_bytes = meta["file_bytes"]
            sha256 = hashlib.sha256(file_bytes).hexdigest()
            fnames.append(fname)
            sha256_list.append(sha256)
            tasks.append(self.vt_client(file_hash=sha256))

        vt_results = await asyncio.gather(*tasks)

        results = {}
        for fname, sha256, vt_result in zip(fnames, sha256_list, vt_results):

            meta_stats = vt_result.get("meta") or {}
            stats = meta_stats.copy() if vt_result.get("status") == "ok" else {}
            stats.pop("resource", None)

            # Remove noisy fields from 'last_analysis_stats'
            if "last_analysis_stats" in stats:
                stats["last_analysis_stats"] = {
                    k: v
                    for k, v in stats["last_analysis_stats"].items()
                    if k not in self.VT_ZERO_FIELDS
                }

            results[fname] = {
                "sha256": sha256,
                "virustotal": {
                    "status": vt_result.get("status"),
                    "reason": vt_result.get("reason"),
                    "stats": stats,
                },
            }

        return results

    # -----------------------------
    # YARA Scan
    # -----------------------------

    def yara_scan(self, verbose: Optional[bool] = None) -> dict:

        verbose = self.yara_verbose if verbose is None else verbose

        if self.yara_engine is None:
            return {
                fname: {
                    "flag": False,
                    "matches": [],
                    "error": "YARA engine not provided",
                }
                for fname in getattr(self, "attachments", {}).keys()
            }

        attachments = self._ensure_attachments()
        results = {}

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

                formatted_matches = []

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
                                strings.append(
                                    {
                                        "name": s.identifier,
                                        "offset": hex(inst.offset),
                                        "data": inst.matched_data.hex(),
                                    }
                                )

                        match_dict["strings"] = strings

                    formatted_matches.append(match_dict)

                results[fname] = {
                    "flag": any(m["flag"] for m in formatted_matches),
                    "matches": formatted_matches,
                }

            except RuntimeError as e:
                results[fname] = {
                    "flag": False,
                    "matches": [],
                    "error": f"YARA runtime error: {str(e)}",
                }

            except Exception as e:
                results[fname] = {
                    "flag": False,
                    "matches": [],
                    "error": f"Unexpected YARA error: {str(e)}",
                }

        return results
