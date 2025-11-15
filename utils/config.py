import os
from dotenv import load_dotenv

load_dotenv()


VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")


SUSPICIOUS_URL_KEYWORDS = {
    "login", "signin", "sign-in", "sign_in", "auth", "authenticate", "authentication",
    "verify", "verification", "confirm", "confirm-account", "approve", "authorize",
    "password", "passwd", "pass", "credential", "credentials", "reset", "reset-password",
    "unlock", "twofactor", "two-factor", "mfa", "otp", "token",


    "account", "accounts", "secure", "secure-login", "secure-account",
    "security", "account-update", "update", "verify-account", "verification-code",
    "reverify", "reconfirm", "challenge",

    
    "billing", "payment", "invoice", "receipt", "payment-info", "card", "credit-card",
    "bank", "banking", "pay", "paypal", "stripe", "appleid", "microsoft", "amazon",
    "ebay", "renew", "subscription", "activation", "activate", "delivery", "shipping"
}


SUSPICIOUS_TLDS = {
    "icu", "xyz", "top", "ru", "cn", "online", "zip", "mov",
    "porn", "xxx", "casino", "poker", "buzz", "support", "sbs",
    "loan", "lol", "info", "bond", "today", "shop", "xin", "gdn",
    "bid", "one", "live", "site", "cfd", "pro", "cc"
}


SHORTENERS = {
    "simpleurl.tech", "sor.bz", "bit.ly", "bitly.kr", "bl.ink", "buff.ly",
    "cutt.ly", "dub.co", "fox.ly", "gg.gg", "han.gl", "kurzelinks.de",
    "kutt.it", "linkhuddle.com", "linksplit.io", "lstu.fr", "bli.nk", 
    "oe.cd", "ow.ly", "rebrandly.com", "reduced.to", "rip.to", 
    "san.aq", "short.io", "lyn.bz", "shorturl.at", "x.gd",
    "smallseotools.com", "spoo.me", "switchy.io", "t2m.io",
    "tinu.be", "tinyurl.com", "t.ly", "urlr.me", "v.gd",
    "vo.la", "yaso.su", "zlnk.com", "rb.gy","tiny.cc",
    "rebrand.ly", "s.id", "tiny.one","n9.cl", "ln.run",
    
}


FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "protonmail.com", "pm.me" "aol.com", "icloud.com", "zoho.com", "gmx.com",
    "yandex.com", "mail.com", "tutanota.com", "fastmail.com", "hushmail.com",
    "mail.ru"
}



# Threshold for "too many" meaningful subdomains
SUBDOMAIN_THRESHOLD = 3

# trivial subdomains to ignore when counting meaningful subdomains.
TRIVIAL_SUBDOMAINS = {
    "www", "m",
    "mail", "webmail", "smtp", "imap", "pop",
    "ns1", "ns2", "dns", "cpanel", "whm",
    "cdn", "static", "assets", "files",
    "backup", "dev", "test"
}


# Maximum allowed difference between Date header and first Received timestamp.
DATE_RECEIVED_DRIFT_MINUTES = 30

#Maximum number of redirects to follow
MAX_REDIRECTS = 10  # Prevents infinite or excessively long redirect chains

# Domain age thresholds (in days)
THRESHOLD_YOUNG = 30      # Domains younger than this are considered "young" and potentially suspicious

THRESHOLD_EXPIRING=10  # Domains expiring in fewer than this many days are flagged as expiring soon
