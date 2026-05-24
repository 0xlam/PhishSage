import asyncio
from datetime import datetime, timezone

import whois
from dateutil import parser

from phishsage.models.whois import WhoisResult


class WhoisService:

    async def lookup(self, domain: str) -> WhoisResult:
        raw = await asyncio.to_thread(whois.whois, domain)

        created = self._normalize_date(raw.creation_date)
        expires = self._normalize_date(raw.expiration_date)

        now = datetime.now(timezone.utc)

        age_days = None
        expiry_days = None

        if created:
            age_days = (now - created).days

        if expires:
            expiry_days = (expires - now).days

        return WhoisResult(
            domain=domain,
            created_at=created,
            expires_at=expires,
            age_days=age_days,
            expiry_days=expiry_days,
            registrar=getattr(raw, "registrar", None),
        )

    def _normalize_date(
        self,
        value,
    ) -> datetime | None:

        if not value:
            return None

        if isinstance(value, list):
            value = value[0]

        if isinstance(value, str):
            value = parser.parse(value)

        if not isinstance(value, datetime):
            return None

        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc)