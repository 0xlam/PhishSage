import os
import re
import base64
import hashlib
import magic
import mimetypes
from pathlib import Path
import yara
from phishsage.utils.api_clients import check_virustotal


def safe_filename(name):
    # Remove any directory components, keep only the file's name
    base_name = os.path.basename(name)

    # Replace any characters not in the allowed set with underscores
    return re.sub(r'[^\w_.-]', '_', base_name) 

def human_readable_size(num_bytes, decimal_places=2):
    """Convert bytes to a human-readable string (KB, MB, GB...)."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    for unit in ["KB", "MB", "GB", "TB"]:
        num_bytes /= 1024.0
        if num_bytes < 1024.0:
            return f"{num_bytes:.{decimal_places}f} {unit}"
    return f"{num_bytes:.{decimal_places}f} GB"

#---------------------------------------------------------------------------------

def parse_all_attachments(mail):
    """
    Parse all attachments in an email once.
    Returns a dict keyed by filename with parsed metadata.
    """
    parsed_attachments = {}

    for attachment in mail.attachments:
        parsed = parse_attachment(attachment)

        # Skip broken/unreadable attachments
        if "error" in parsed:
            continue

        filename = parsed["filename"]
        parsed_attachments[filename] = parsed

    return parsed_attachments


def parse_attachment(attachment):
    """Parse and validate a single attachment: decode from base64, detect MIME, extract metadata."""
    filename = safe_filename(attachment.get('filename', 'unnamed'))

    #Decode the base64-encoded file payload into raw bytes
    try:
        file_bytes = base64.b64decode(attachment['payload'])
    except Exception as e:
        return {"error": f"Invalid base64 payload for {filename}: {e}"}

    # Use 'magic' to detect file MIME type based on content
    try:
        mime_type = magic.from_buffer(file_bytes, mime=True)
    except Exception as e:
        return {"error": f"Cannot determine file type for {filename}: {e}"}

    #Extract file extension and and calculate file size
    ext = os.path.splitext(filename)[1].lower()
    size_bytes = len(file_bytes)
    size_human = human_readable_size(size_bytes)

    # Check actual detected type
    guessed_ext = mimetypes.guess_extension(mime_type) or ''

    # Return a dictionary with all parsed attachment metadata
    return {
        "filename": filename,
        "file_bytes": file_bytes,
        "mime_type": mime_type,
        "extension": ext,
        "detected_ext": guessed_ext,
        "size_bytes": size_bytes,
        "size_human": size_human
       
    }


def extract_attachments(parsed_attachments, save_dir="attachments", save_files=True):
    """
    Save parsed attachments to disk.
    Returns a dict: {filename: saved_path}
    """
    os.makedirs(save_dir, exist_ok=True)
    results = {}

    for filename, parsed in parsed_attachments.items():
        if "error" in parsed or "file_bytes" not in parsed:
            continue

        if save_files:
            path = os.path.join(save_dir, filename)

            # Avoid overwriting by adding suffix (_1, _2, …)
            counter = 1
            base, ext = os.path.splitext(filename)
            while os.path.exists(path):
                path = os.path.join(save_dir, f"{base}_{counter}{ext}")
                counter += 1

            with open(path, "wb") as f:
                f.write(parsed["file_bytes"])

            results[filename] = path
        else:
            results[filename] = None

    return results


def list_attachments(parsed_attachments):
    """Return a summary dict of attachments (no saving or scanning)."""
    summary = {}

    for filename, parsed in parsed_attachments.items():
        if "error" in parsed:
            continue

        summary[filename] = {
            "size_human": parsed.get("size_human"),
            "mime_type": parsed.get("mime_type"),
            "extension": parsed.get("extension"),
            "detected_ext": parsed.get("detected_ext"),
        }

    return summary


def hash_attachments(parsed_attachments):
    """Compute MD5, SHA1, and SHA256 hashes for each attachment."""
    hashed = {}

    for filename, parsed in parsed_attachments.items():
        if "error" in parsed:
            continue

        file_bytes = parsed["file_bytes"]
        
        hashed[parsed["filename"]] = {
            "md5": hashlib.md5(file_bytes).hexdigest(),
            "sha1": hashlib.sha1(file_bytes).hexdigest(),
            "sha256": hashlib.sha256(file_bytes).hexdigest()
        }

    return hashed


def scan_attachments(parsed_attachments):
    """Scan email attachments on VirusTotal using SHA256 and normalize output."""
    scanned = {}

    for filename, parsed in parsed_attachments.items():
        if "error" in parsed:
            continue

        file_bytes = parsed["file_bytes"]
        sha256 = hashlib.sha256(file_bytes).hexdigest()

        vt_result = check_virustotal(file_hash=sha256)

        meta = vt_result.get("meta") or {}
        stats = (meta.copy() if vt_result.get("status") == "ok" else {})

        # Remove VT-internal reference
        stats.pop("resource", None)
        stats.pop("error", None)

        scanned[filename] = {
            "sha256": sha256,
            "virustotal": {
                "status": vt_result.get("status"),
                "reason": vt_result.get("reason"),
                "stats": stats
            }
        }

    return scanned


def yara_scan_attachments(parsed_attachments, rules_path, verbose=False):
    """
    Scans all parsed attachments using one or multiple YARA rule files.
    """
    results = {}

    # Normalize rules_path into a list of file paths
    if isinstance(rules_path, (str, Path)):
        path_obj = Path(rules_path)

        if path_obj.is_dir():
            # Recursively find all .yar/.yara files (case-insensitive)
            rule_files = [
                str(p) for p in path_obj.rglob("*")
                if p.is_file()
                and p.suffix.lower() in {'.yar', '.yara'}
                and not p.name.startswith('.')          # skip hidden files
                and not p.name.endswith('~')            
            ]
            if not rule_files:
                return {"error": f"No .yar/.yara files found in directory: {rules_path}"}
            rule_paths = rule_files
        else:
            # Single file
            rule_paths = [str(path_obj)]

    elif isinstance(rules_path, (list, tuple)):

        rule_paths = []
        for item in rules_path:
            path_obj = Path(item)
            if path_obj.is_dir():
                # Expand directory
                dir_files = [
                    str(p) for p in path_obj.rglob("*")
                    if p.is_file()
                    and p.suffix.lower() in {'.yar', '.yara'}
                    and not p.name.startswith('.')
                    and not p.name.endswith('~')
                ]
                if not dir_files:
                    return {"error": f"No .yar/.yara files found in directory passed in list: {item}"}
                rule_paths.extend(dir_files)
            else:
                rule_paths.append(str(path_obj))
    else:
        return {"error": "rules_path must be a string, list of strings, or directory path"}

    if not rule_paths:
        return {"error": "No valid YARA rule files provided"}

    # Compile all rules
    compiled_rules = []
    for path in rule_paths:
        if not os.path.isfile(path):
            return {"error": f"YARA rules file not found: {path}"}

        try:
            rules = yara.compile(filepath=path)
            compiled_rules.append(rules)
        except yara.SyntaxError as e:
            return {"error": f"YARA syntax error in {path}: {str(e)}"}
        except Exception as e:
            return {"error": f"Failed to compile YARA rules from {path}: {str(e)}"}

    if not compiled_rules:
        return {"error": "No valid YARA rules could be loaded"}

    # Step 3: Scan each attachment with every ruleset
    for filename, attachment in parsed_attachments.items():
        if "error" in attachment or "file_bytes" not in attachment:
            results[filename] = {"error": attachment.get("error", "No file_bytes")}
            continue

        file_bytes = attachment["file_bytes"]
        all_matches = []

        for rules in compiled_rules:
            try:
                matches = rules.match(data=file_bytes)
                all_matches.extend(matches)
            except Exception as e:
                results[filename] = {"error": f"Scan failed: {str(e)}"}
                break

        if "error" in results.get(filename, {}):
            continue

        # Format results
        attachment_result = {"matches": []}
        for match in all_matches:
            matched_flag = bool(match.strings)

            match_dict = {
                "flag": matched_flag,
                "rule": match.rule,
                "namespace": match.namespace,
                "rule_meta": match.meta or {},
            }

            if verbose and matched_flag:
                match_dict["strings"] = []
                for s in match.strings:
                    for inst in s.instances:
                        match_dict["strings"].append({
                            "name": s.identifier,
                            "offset": hex(inst.offset),
                            "data": inst.matched_data.hex()
                        })

            attachment_result["matches"].append(match_dict)

        attachment_result["flag"] = any(m["flag"] for m in attachment_result["matches"])

        results[filename] = {
            "flag": attachment_result["flag"],
            "matches": attachment_result["matches"]
        }

    return results


def process_attachments(mail, action="list", **kwargs):
    """
    Entry point to process attachments.
    Actions: "list", "extract", "hash", "scan"
    Extra args (kwargs) are passed to the underlying function.
    """
    parsed = parse_all_attachments(mail)
  

    if action == "list":
        return list_attachments(parsed)

    elif action == "extract":
        return extract_attachments(parsed, **kwargs)

    elif action == "hash":
        return hash_attachments(parsed)

    elif action == "scan":
        return scan_attachments(parsed)

    elif action == "yara":
        return yara_scan_attachments(parsed, **kwargs)

    elif action == "heuristics":
        pass

    else:
        raise ValueError(f"Unknown action: {action}")
