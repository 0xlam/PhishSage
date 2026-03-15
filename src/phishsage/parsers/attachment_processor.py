import os
import re
import base64
import hashlib
import mimetypes
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

import magic


class AttachmentProcessor:
    """
    Processes email attachments safely and efficiently.

    Provides utilities to:
        • Parse and cache attachments from a mail object
        • Detect true MIME types (not trusting extensions)
        • List attachment metadata
        • Extract files to disk with safe naming
        • Generate MD5, SHA1, and SHA256 hashes

        Parsing is lazy by default and results are cached to avoid
        repeated  decoding. You can force immediate parsing using
        `force_parse()` after initialization.

        Invalid or corrupted attachments are skipped, not fatal.
    """

    VT_ZERO_FIELDS = {
        "timeout",
        "confirmed-timeout",
        "failure",
        "type-unsupported",
        "resource",
        "error",
    }

    def __init__(
        self,
        mail,
        default_save_dir: str = "attachments",
    ):

        self.mail = mail
        self.default_save_dir = default_save_dir

        self._parsed_cache: Optional[Dict[str, Dict[str, Any]]] = None

    # ---------------------Parsing -----------------------------
    def force_parse(self):
        """Force-parse all attachments now and return parsed attachments."""
        self._ensure_parsed()
        return self._parsed_cache 

    def _ensure_parsed(self) -> Dict[str, Dict[str, Any]]:
        if self._parsed_cache is None:
            self._parsed_cache = self._parse_all()
        return self._parsed_cache

    def _parse_all(self) -> Dict[str, Dict[str, Any]]:
        parsed_attachments = {}

        for attachment in self.mail.attachments:
            parsed = self._parse_single(attachment)

            if "error" in parsed:
                continue

            parsed_attachments[parsed["filename"]] = parsed

        return parsed_attachments

    def _parse_single(self, attachment: Dict[str, Any]) -> Dict[str, Any]:
        filename = self._safe_filename(attachment.get("filename", "unnamed"))

        try:
            file_bytes = base64.b64decode(attachment["payload"])
        except Exception as e:
            return {"error": f"Invalid base64 payload for {filename}: {e}"}

        try:
            mime_type = magic.from_buffer(file_bytes, mime=True)
        except Exception as e:
            return {"error": f"Cannot determine file type for {filename}: {e}"}

        ext = os.path.splitext(filename)[1].lower()
        size_bytes = len(file_bytes)

        return {
            "filename": filename,
            "file_bytes": file_bytes,
            "mime_type": mime_type,
            "extension": ext,
            "detected_ext": mimetypes.guess_extension(mime_type) or "",
            "size_bytes": size_bytes,
            "size_human": self._human_readable_size(size_bytes),
        }

    # -------------------- Actions -------------------------------

    def list(self):
        parsed = self._ensure_parsed()
        summary = {}

        for filename, parsed_data in parsed.items():
            summary[filename] = {
                "size_human": parsed_data.get("size_human"),
                "mime_type": parsed_data.get("mime_type"),
                "extension": parsed_data.get("extension"),
                "detected_ext": parsed_data.get("detected_ext"),
            }

        return summary

    def extract(self, save_dir: Optional[str] = None, save_files: bool = True):
        parsed = self._ensure_parsed()
        save_dir = save_dir if save_dir is not None else self.default_save_dir

        os.makedirs(save_dir, exist_ok=True)

        results = {}

        for filename, parsed_data in parsed.items():
            if "file_bytes" not in parsed_data:
                continue

            if not save_files:
                results[filename] = None
                continue

            path = self._unique_path(save_dir, filename)

            with open(path, "wb") as f:
                f.write(parsed_data["file_bytes"])

            results[filename] = path

        return results

    def hash(self):
        parsed = self._ensure_parsed()
        hashed = {}

        for filename, parsed_data in parsed.items():
            file_bytes = parsed_data["file_bytes"]

            hashed[filename] = {
                "md5": hashlib.md5(file_bytes).hexdigest(),
                "sha1": hashlib.sha1(file_bytes).hexdigest(),
                "sha256": hashlib.sha256(file_bytes).hexdigest(),
            }

        return hashed

    # -------------------- Utilities -----------------------------

    @staticmethod
    def _safe_filename(name: str) -> str:
        base_name = os.path.basename(name)
        return re.sub(r"[^\w_.-]", "_", base_name)

    @staticmethod
    def _human_readable_size(num_bytes: int, decimal_places: int = 2) -> str:
        if num_bytes < 1024:
            return f"{num_bytes} B"

        for unit in ["KB", "MB", "GB", "TB"]:
            num_bytes /= 1024.0
            if num_bytes < 1024.0:
                return f"{num_bytes:.{decimal_places}f} {unit}"

        return f"{num_bytes:.{decimal_places}f} GB"

    @staticmethod
    def _unique_path(directory: str, filename: str) -> str:
        path = os.path.join(directory, filename)
        base, ext = os.path.splitext(filename)
        counter = 1

        while os.path.exists(path):
            path = os.path.join(directory, f"{base}_{counter}{ext}")
            counter += 1

        return path
