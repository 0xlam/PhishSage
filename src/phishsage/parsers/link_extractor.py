from bs4 import BeautifulSoup

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
