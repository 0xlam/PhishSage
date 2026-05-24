try:
    import vt
except ImportError as exc:
    raise ImportError(
        "VirusTotal scanning requires additional dependencies. "
        "Install with: pip install phishsage[virustotal]"
    ) from exc

from phishsage.models.virustotal import VirusTotalResult, VirusTotalStats

class VirusTotalService:
    def __init__(self, api_key: str):
        self.api_key = api_key

    async def lookup_url(self, url: str) -> VirusTotalResult:
        return await self._lookup(resource=url, resource_type="url")

    async def lookup_file_hash(self, file_hash: str) -> VirusTotalResult:
        return await self._lookup(resource=file_hash, resource_type="file")

    async def _lookup(self, resource: str, resource_type: str) -> VirusTotalResult:
        if not self.api_key:
            return VirusTotalResult(
                status="auth_error",
                resource=resource,
                stats=None,
                error="missing_api_key",
            )

        try:
            async with vt.Client(self.api_key) as client:
                if resource_type == "url":
                    url_id = vt.url_id(resource)
                    obj = await client.get_object_async("/urls/{}", url_id)
                else:
                    obj = await client.get_object_async("/files/{}", resource)

                raw_stats = dict(obj.get("last_analysis_stats", {}) or {})

                stats = VirusTotalStats(
                    malicious=raw_stats.get("malicious", 0),
                    suspicious=raw_stats.get("suspicious", 0),
                    harmless=raw_stats.get("harmless", 0),
                    undetected=raw_stats.get("undetected", 0),
                    timeout=raw_stats.get("timeout", 0),
                )

                return VirusTotalResult(
                    status="ok",
                    resource=resource,
                    stats=stats,
                    last_analysis_date=getattr(obj, "last_analysis_date", None),
                    first_submission_date=getattr(obj, "first_submission_date", None),
                )

        except vt.APIError as e:
            err_code = (
                (getattr(e, "code", "") or "")
                .lower()
                .replace("error", "")
                .strip("_")
            )

            if err_code == "notfound":
                return VirusTotalResult(
                    status="not_found",
                    resource=resource,
                    stats=None,
                    error=str(e),
                )
            elif err_code in ("authenticationrequired", "forbidden"):
                return VirusTotalResult(
                    status="auth_error",
                    resource=resource,
                    stats=None,
                    error=str(e),
                )
            elif err_code in ("quotaexceeded", "ratelimit"):
                return VirusTotalResult(
                    status="rate_limited",
                    resource=resource,
                    stats=None,
                    error=str(e),
                )
            else:
                return VirusTotalResult(
                    status="error",
                    resource=resource,
                    stats=None,
                    error=str(e),
                )