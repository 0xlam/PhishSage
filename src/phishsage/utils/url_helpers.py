import math
import re
from collections import Counter
from urllib.parse import urlparse, urlunparse

import aiohttp
import asyncio
import requests
import tldextract
from bs4 import BeautifulSoup

from phishsage.config.loader import MAX_REDIRECTS


def normalize_url(url):
    url = url.strip()
    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url.lstrip("/")

    url = re.sub(r"(https?://)/+", r"\1", url)

    parsed = urlparse(url)
    if not parsed.netloc:
        return ""

    normalized = urlunparse(
        (
            "https",
            parsed.netloc.lower(),
            parsed.path or "/",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )

    return normalized


def get_hostname(url):
    try:
        parsed = urlparse(normalize_url(url))
        raw_hostname = parsed.hostname
        if not raw_hostname:
            return ""

        punycode_hostname = raw_hostname.encode("idna").decode("ascii")
        return punycode_hostname.lower()  # lowercase the ASCII form
    except Exception:
        return ""


def extract_domain_parts(url):
    hostname = get_hostname(url)
    if not hostname:
        return None, None, None, None

    extracted = tldextract.extract(hostname)
    registered = extracted.domain + "." + extracted.suffix
    if not registered:
        return None, None, None, None

    return registered, extracted.domain, extracted.subdomain, extracted.suffix


def shannon_entropy(s):
    if not s:
        return 0.0
    prob = Counter(s).values()
    prob = [p / len(s) for p in prob]
    return -sum(p * math.log2(p) for p in prob)


def extract_links(html_body):
    if not html_body.strip():
        return []

    soup = BeautifulSoup(html_body, "html.parser")
    links = []

    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href", "").strip()

        if href:
            links.append(href)

    unique_links = list(dict.fromkeys(links))
    return unique_links


async def get_redirect_chain(
    parsed,
    session: aiohttp.ClientSession,
    max_redirects=MAX_REDIRECTS,
):

    url = parsed.normalized

    try:
        async with session.get(
            url,
            allow_redirects=True,
            max_redirects=max_redirects,
        ) as response:

            history = response.history

            chain = [r.url.human_repr() for r in history] + [
                response.url.human_repr()
            ]

            statuses = [r.status for r in history] + [response.status]

            final_url = response.url.human_repr()
            redirect_count = len(chain) - 1

            return {
                "original_url": url,
                "redirect_chain": chain,
                "status_codes": statuses,
                "final_url": final_url,
                "final_status": response.status,
                "redirect_count": redirect_count,
                "redirected": redirect_count > 0,
            }

    except aiohttp.TooManyRedirects:
        return {
            "original_url": url,
            "error": "Too many redirects",
            "redirect_chain": [],
            "status_codes": [],
            "redirect_count": max_redirects,
            "redirected": True,
        }

    except asyncio.TimeoutError:
        return {
            "original_url": url,
            "error": "Request timeout",
            "redirect_chain": [],
            "status_codes": [],
            "redirect_count": 0,
            "redirected": False,
        }

    except aiohttp.ClientError as e:
        return {
            "original_url": url,
            "error": str(e),
            "redirect_chain": [],
            "status_codes": [],
            "redirect_count": 0,
            "redirected": False,
        }
