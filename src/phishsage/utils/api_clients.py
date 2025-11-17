import base64
import requests
from phishsage.config.loader import  VIRUSTOTAL_API_KEY


session = requests.Session()

def safe_request(
    url,
    method="GET",
    headers=None,
    data=None,
    json=None,
    timeout=10,
    max_size=2 * 1024 * 1024,
    verify=True,
    debug=False,
):
  

    method = method.upper()
    try:
        # Stream only for GET requests
        stream = method == "GET"

        resp = session.request(
            method,
            url,
            headers=headers,
            data=data,
            json=json,
            timeout=timeout,
            stream=stream,
            verify=verify,
        )
        resp.raise_for_status()

        # Handle content safely
        if stream:
            total = 0
            chunks = []
            for chunk in resp.iter_content(chunk_size=8192):
                total += len(chunk)
                if total > max_size:
                    raise ValueError("Response too large")
                chunks.append(chunk)
            content = b"".join(chunks)
        else:
            content = resp.content
            if len(content) > max_size:
                raise ValueError("Response too large")

        return {"ok": True, "response": resp, "content": content, "error": None}

    except requests.Timeout:
        err = "Timeout"
    except requests.ConnectionError:
        err = "Connection Error"
    except requests.RequestException as e:
        err = f"Request failed: {e}"
    except ValueError as e:
        err = str(e)
    except Exception as e:
        err = f"Unexpected: {e}"

    if debug:
        print(f"[!] {method} {url} failed -> {err}")

    return {"ok": False, "response": None, "content": None, "error": err}


def check_virustotal(file_hash=None, url=None, debug=False):
    if not VIRUSTOTAL_API_KEY:
        return {"warning": "API key missing (skipping VirusTotal check)"}

    if url and file_hash:
        return {"error": "Provide only one of file_hash or url"}

    if not (url or file_hash):
        return {"error": "No file_hash or url provided"}

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    # Construct endpoint
    if url:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    # Request using safe_request
    result = safe_request(endpoint, method="GET", headers=headers, debug=debug)

    if not result["ok"]:
        return {"error": result["error"]}

    try:
        res_json = result["response"].json()
    except Exception:
        return {"error": "Invalid JSON response from VirusTotal"}

    # Check for VirusTotal-specific errors
    if "error" in res_json:
        err_code = res_json["error"].get("code", "")
        err_msg = res_json["error"].get("message", "")
        return {"error": f"VT Error: {err_code or ''} {err_msg or ''}".strip()}

    # Extract results
    data = res_json.get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats")

    if stats:
        return stats

    return {"error": "Unexpected response format", "raw": res_json}

