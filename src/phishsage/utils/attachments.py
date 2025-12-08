import os
import re
import base64
import hashlib
import magic
import mimetypes
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
    """Scan email attachments on VirusTotal using their SHA256 hash and extract relevant stats."""
    scanned = {}

    for filename, parsed in parsed_attachments.items():
        if "error" in parsed:
            continue

        file_bytes = parsed["file_bytes"]
        sha256 = hashlib.sha256(file_bytes).hexdigest()

        vt_result = check_virustotal(file_hash=sha256)

        # Extract stats excluding the 'resource' key
        meta_stats = {
            k: v for k, v in vt_result.get("meta", {}).items() if k != "resource"
        }

        extracted_vt = {
            "status": vt_result.get("status"),
            "flags": vt_result.get("flags", []),
            "meta": meta_stats
        }

        scanned[filename] = {
            "sha256": sha256,
            "virustotal": extracted_vt,
        }

    return scanned

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

    elif action == "heuristics":
        pass

    else:
        raise ValueError(f"Unknown action: {action}")
