import html
import re

from urlextract import URLExtract

extractor = URLExtract(cache_dns=False)


def extract_links(body):
    if not body.strip():
        return []

    body = html.unescape(body)
    links = extractor.find_urls(body)
    links = [re.sub(r"[.,;:!?()\[\]{}]+$", "", u) for u in links]

    return list(dict.fromkeys(links))