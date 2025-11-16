import requests
import idna
import math
import tldextract
from collections import Counter
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from phishsage.utils.config import MAX_REDIRECTS


def normalize_url(url):
    return url if url.startswith("http") else f"https://{url}"


def get_hostname(url):
    hostname = urlparse(normalize_url(url)).hostname or ""
    try:
        hostname = hostname.encode('utf-8').decode('idna')
    except Exception:
        pass
    return hostname.lower()


def extract_domain_parts(url):
    hostname = get_hostname(url)
    extracted = tldextract.extract(hostname)
    return extracted.domain + '.' + extracted.suffix, extracted.domain, extracted.subdomain, extracted.suffix


def shannon_entropy(s):
    """
    Calculate Shannon entropy of a string.
    A higher entropy indicates more randomness (less human-readable).
    """
    if not s:
        return 0.0

    counts = Counter(s)
    length = len(s)

    # Shannon Entropy formula: -Σ (p_i * log2(p_i))
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 3)


def extract_links(html_body):
    if not html_body.strip():
        return []
    
    soup = BeautifulSoup(html_body, "html.parser")
    links = []

    for anchor in soup.find_all("a",href=True):
        href = anchor.get("href", "").strip()

        if href:
            links.append(href)

    unique_links = list(dict.fromkeys(links))
    return unique_links

def get_redirect_chain(url, max_redirects=MAX_REDIRECTS):
    try:
        session = requests.Session()
        session.max_redirects = max_redirects
        response = session.get(url, allow_redirects=True, timeout=(3, 5), stream=True)

        chain = [r.url for r in response.history] + [response.url]
        statuses = [r.status_code for r in response.history] + [response.status_code]
        final_url = response.url
        redirect_count = len(chain) - 1

        return {
            "original_url": url,
            "redirect_chain": chain,
            "status_codes": statuses,
            "final_url": final_url,
            "final_status": response.status_code,
            "redirect_count": redirect_count,
            "redirected": redirect_count > 0
        }

    except requests.exceptions.TooManyRedirects:
        return {
            "original_url": url,
            "error": "Too many redirects",
            "redirect_chain": [],
            "status_codes": [],
            "redirect_count": max_redirects,
            "redirected": True
        }

    except requests.exceptions.RequestException as e:
        return {
            "original_url": url,
            "error": str(e),
            "redirect_chain": [],
            "status_codes": [],
            "redirect_count": 0,
            "redirected": False
        }

