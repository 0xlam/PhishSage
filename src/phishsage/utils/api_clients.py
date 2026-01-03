import vt
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



def check_virustotal(file_hash = None, url = None):
    if not VIRUSTOTAL_API_KEY:
        return {
            "status": "auth_error",
            "reason": "missing_api_key",
            "meta": {}
        }

    if url and file_hash:
        return {
            "status": "error",
            "reason": "invalid_input",
            "meta": {"details": "Provide only file_hash OR url, not both"}
        }

    if not (url or file_hash):
        return {
            "status": "error",
            "reason": "missing_parameters",
            "meta": {}
        }

    resource = url or file_hash

    try:
        with vt.Client(VIRUSTOTAL_API_KEY) as client:
            if url:
                url_id = vt.url_id(url)
                obj = client.get_object("/urls/{}", url_id)
            else:
                obj = client.get_object("/files/{}", file_hash)

            stats = obj.last_analysis_stats
            if stats is None:
                return {
                    "status": "error",
                    "reason": "unexpected_format",
                    "meta": {"resource": resource}
                }

            return {
                "status": "ok",
                "reason": None,
                "meta": {**stats, "resource": resource}
            }

    except vt.APIError as e:
        err_code = (getattr(e, 'code', '') or "").lower().replace("error", "").strip("_")

        if err_code == "notfound":
            return {
                "status": "not_found",
                "reason": "not_found",
                "meta": {"resource": resource, "error": str(e)}
            }

        elif err_code in ("authenticationrequired", "forbidden"):
            return {
                "status": "auth_error",
                "reason": "invalid_api_key",
                "meta": {"resource": resource, "error": str(e)}
            }

        elif err_code in ("quotaexceeded", "ratelimit"):
            return {
                "status": "rate_limited",
                "reason": "rate_limited",
                "meta": {"resource": resource, "error": str(e)}
            }

        else:
            return {
                "status": "error",
                "reason": err_code or "api_error",
                "meta": {"resource": resource, "error": str(e)}
            }