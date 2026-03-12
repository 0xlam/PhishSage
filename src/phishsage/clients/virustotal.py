import vt
import base64
from phishsage.config.loader import VIRUSTOTAL_API_KEY


async def check_virustotal(file_hash=None, url=None):
    if not VIRUSTOTAL_API_KEY:
        return {"status": "auth_error", "reason": "missing_api_key", "meta": {}}

    if url and file_hash:
        return {
            "status": "error",
            "reason": "invalid_input",
            "meta": {"details": "Provide only file_hash OR url, not both"},
        }

    if not (url or file_hash):
        return {"status": "error", "reason": "missing_parameters", "meta": {}}

    resource = url or file_hash

    try:
        async with vt.Client(VIRUSTOTAL_API_KEY) as client:
            if url:
                url_id = vt.url_id(url)
                obj = await client.get_object_async("/urls/{}", url_id)
            else:
                obj = await client.get_object_async("/files/{}", file_hash)

            stats = dict(obj.get("last_analysis_stats", {}))

            if not stats:
                return {
                    "status": "error",
                    "reason": "unexpected_format",
                    "meta": {"resource": resource},
                }

            last_dt = getattr(obj, "last_analysis_date", None)
            first_dt = getattr(obj, "first_submission_date", None)

            return {
                "status": "ok",
                "reason": None,
                "meta": {
                    "resource": resource,
                    "last_analysis_stats": stats,
                    "last_analysis_date": last_dt.isoformat() if last_dt else None,
                    "first_submission_date": first_dt.isoformat() if first_dt else None,
                },
            }

    except vt.APIError as e:
        err_code = (
            (getattr(e, "code", "") or "").lower().replace("error", "").strip("_")
        )

        if err_code == "notfound":
            return {
                "status": "not_found",
                "reason": "not_found",
                "meta": {"resource": resource, "error": str(e)},
            }

        elif err_code in ("authenticationrequired", "forbidden"):
            return {
                "status": "auth_error",
                "reason": "invalid_api_key",
                "meta": {"resource": resource, "error": str(e)},
            }

        elif err_code in ("quotaexceeded", "ratelimit"):
            return {
                "status": "rate_limited",
                "reason": "rate_limited",
                "meta": {"resource": resource, "error": str(e)},
            }

        else:
            return {
                "status": "error",
                "reason": err_code or "api_error",
                "meta": {"resource": resource, "error": str(e)},
            }