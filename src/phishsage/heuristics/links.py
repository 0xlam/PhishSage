import re
import math
import asyncio
import ipaddress
from collections import Counter

from phishsage.parsers import parse_url


def _ok(reasons=None, details=None):
    return {
        "status": "ok",
        "flags": bool(reasons),
        "reasons": list(reasons) if reasons else [],
        "details": details or {},
    }


def _error(message, **extra):
    return {
        "status": "error",
        "flags": False,
        "reasons": [],
        "details": {
            "error": str(message),
            **extra,
        },
    }


def _skipped(missing):
    return {
        "status": "skipped",
        "flags": False,
        "reasons": [],
        "details": {"missing": missing},
    }


def _parsed_details(parsed):
    return {
        "raw": parsed.raw,
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "registered_domain": parsed.registered_domain,
        "domain": parsed.domain,
        "subdomain": parsed.subdomain,
        "suffix": parsed.suffix,
        "path": parsed.path,
        "query": list(parsed.query.items()),
    }


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value).values()
    probabilities = [count / len(value) for count in counts]

    return -sum(p * math.log2(p) for p in probabilities)


def ip_based(parsed) -> dict:
    hostname = parsed.hostname

    if not hostname:
        return _skipped("hostname")

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return _ok()

    return _ok(
        reasons=["ip_based_url"],
        details={"ip_version": ip.version},
    )


def suspicious_tld(parsed, config) -> dict:
    suffix = (parsed.suffix or "").lower()

    if not suffix:
        return _skipped("suffix")

    if suffix in {t.lower() for t in config.suspicious_tlds}:
        return _ok(
            reasons=["known_suspicious_tld"],
            details={"matched_tld": suffix},
        )

    return _ok(reasons=[], details={})


def embedded_tld(parsed, config) -> dict:
    subdomain = parsed.subdomain or ""
    domain = parsed.domain or ""

    common = {t.lower() for t in config.common_tlds}

    def find_matches(value):
        segments = re.split(r"[-.]", value.lower())
        return sorted({segment for segment in segments if segment in common})

    subdomain_matches = find_matches(subdomain)
    domain_matches = find_matches(domain)

    reasons = []

    if domain_matches:
        reasons.append("embedded_fake_tld_in_domain")

    if subdomain_matches:
        reasons.append("embedded_fake_tld_in_subdomain")

    return _ok(
        reasons=reasons,
        details=(
            {
                "domain_matches": domain_matches,
                "subdomain_matches": subdomain_matches,
            }
            if reasons
            else {}
        ),
    )


def shortened_url(parsed, config) -> dict:
    domain = parsed.registered_domain

    if not domain:
        return _skipped("registered_domain")

    if domain.lower() in {s.lower() for s in config.shorteners}:
        return _ok(
            reasons=["url_shortener"],
            details={"matched_domain": domain},
        )

    return _ok(reasons=[], details={})


def abusable_platform(parsed, config) -> dict:
    domain = parsed.registered_domain

    if not domain:
        return _skipped("registered_domain")

    if domain.lower() in {p.lower() for p in config.abusable_platform_domains}:
        return _ok(
            reasons=["abusable_platform"],
            details={"matched_domain": domain},
        )

    return _ok(reasons=[], details={})


def domain_entropy(parsed, config) -> dict:
    sub = parsed.subdomain or ""
    dom = parsed.domain or ""

    sub_ent = shannon_entropy(sub)
    dom_ent = shannon_entropy(dom)

    reasons = []

    if len(sub) >= 8 and sub_ent >= config.entropy_threshold:
        reasons.append("high_subdomain_entropy")

    if len(dom) >= 6 and dom_ent >= config.entropy_threshold:
        reasons.append("high_domain_entropy")

    return _ok(
        reasons=reasons,
        details={
            "subdomain_entropy": sub_ent,
            "domain_entropy": dom_ent,
        },
    )


async def domain_age(parsed, config, deps) -> dict:
    domain = parsed.registered_domain

    if not domain:
        return _skipped("registered_domain")

    if not deps.whois_lookup:
        return _skipped("whois_lookup")

    try:
        w = await deps.whois_lookup(domain)

        reasons = []

        if w.age_days is not None and w.age_days < config.threshold_young:
            reasons.append("young_domain")

        if w.expiry_days is not None:
            if w.expiry_days < 0:
                reasons.append("domain_expired")
            elif w.expiry_days <= config.threshold_expiring:
                reasons.append("domain_expiring_soon")

        return _ok(
            reasons=reasons,
            details={
                "age_days": w.age_days,
                "expiry_days": w.expiry_days,
                "registrar": w.registrar,
                "created_at": w.created_at.isoformat() if w.created_at else None,
                "expires_at": w.expires_at.isoformat() if w.expires_at else None,
            },
        )

    except Exception as e:
        return _error(e)


async def certificate(parsed, config, deps) -> dict:
    hostname = parsed.hostname

    if not hostname:
        return _skipped("hostname")

    if not deps.ssl_fetcher:
        return _skipped("ssl_fetcher")

    try:
        cert = await deps.ssl_fetcher(hostname)

        reasons = []

        if cert.days_until_expiry < 0:
            reasons.append("expired_certificate")

        if 0 <= cert.days_since_issued <= config.cert_recent_issue_days_threshold:
            reasons.append("recently_issued_certificate")

        return _ok(
            reasons=reasons,
            details={
                "days_since_issued": cert.days_since_issued,
                "days_until_expiry": cert.days_until_expiry,
                "issuer": cert.issuer,
                "subject": cert.subject,
                "valid_from": cert.valid_from,
                "valid_to": cert.valid_to,
            },
        )

    except Exception as e:
        return _error(e)


async def redirect_chain(parsed, deps) -> dict:
    if not deps.redirect_lookup:
        return _skipped("redirect_lookup")

    try:
        result = await deps.redirect_lookup(parsed.normalized)

        if result.redirected and not result.chain:
            return _ok(
                reasons=["excessive_redirects"],
                details={
                    "redirect_count": result.redirect_count,
                    "max_redirects": result.redirect_count
                },
            )

        if not result.chain:
            return _error("empty_redirect_chain")


        return _ok(
            details={
                "redirected": result.redirected,
                "final_url": result.final_url,
                "final_status": result.final_status,
                "redirect_chain": result.chain,
                "status_codes": result.status_codes,
                "redirect_count": result.redirect_count,
            },
        )

    except Exception as e:
        return _error(e)


async def virustotal(parsed, deps) -> dict:
    if not deps.vt_lookup:
        return _skipped("vt_lookup")

    try:
        vt = await deps.vt_lookup(parsed.normalized)

        if vt.status != "ok":
            return _error(
                getattr(vt, "error", None) or vt.status or "failed",
                service_status=vt.status,
            )

        stats = vt.stats

        if stats is None:
            return _error("missing_analysis_stats")

        reasons = []

        if stats.malicious > 0:
            reasons.append("vt_malicious")

        if stats.suspicious > 0:
            reasons.append("vt_suspicious")

        return _ok(
            reasons=reasons,
            details={
                "resource": vt.resource,
                "last_analysis_date": vt.last_analysis_date,
                "first_submission_date": vt.first_submission_date,
                "malicious": stats.malicious,
                "suspicious": stats.suspicious,
                "harmless": stats.harmless,
                "undetected": stats.undetected,
            },
        )

    except Exception as e:
        return _error(e)


async def analyze_single_url(url, config, deps, enrich=None) -> dict:
    parsed = parse_url(url)

    if parsed is None:
        return {
            "url": url,
            "status": "skipped",
            "checks": {},
            "enrichment": {},
            "aggregated_flags": [],
        }

    heuristics = {
        "ip_based": ip_based(parsed),
        "suspicious_tld": suspicious_tld(parsed, config),
        "embedded_tld": embedded_tld(parsed, config),
        "shortened_url": shortened_url(parsed, config),
        "abusable_platform": abusable_platform(parsed, config),
        "domain_entropy": domain_entropy(parsed, config),
    }

    enrichers = {
        "domain_age": lambda: domain_age(parsed, config, deps),
        "certificate": lambda: certificate(parsed, config, deps),
        "redirect_chain": lambda: redirect_chain(parsed, deps),
        "virustotal": lambda: virustotal(parsed, deps),
    }

    requested = list(enrichers) if "all" in enrich else (enrich or [])

    unknown = set(requested) - enrichers.keys()
    if unknown:
        raise ValueError(f"Unknown enrichment: {sorted(unknown)}")

    tasks = {name: enrichers[name]() for name in requested}

    results = await asyncio.gather(*tasks.values()) if tasks else []

    enrichment = dict(zip(tasks, results))

    checks = {**heuristics, **enrichment}

    flags = sorted(
        {reason for result in checks.values() for reason in result["reasons"]}
    )

    statuses = {result["status"] for result in checks.values()}

    return {
        "url": parsed.normalized,
        "parsed": _parsed_details(parsed),
        "status": (
            "partial" if any(s in statuses for s in ("error", "skipped")) else "ok"
        ),
        "checks": heuristics,
        "enrichment": enrichment,
        "aggregated_flags": flags,
    }


async def analyze_urls(urls, config, deps, enrich=None) -> list[dict]:
    return await asyncio.gather(
        *(analyze_single_url(url, config, deps, enrich) for url in urls)
    )
