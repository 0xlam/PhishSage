import aiohttp
import asyncio
from phishsage.models.redirect import RedirectResult


class RedirectService:
    def __init__(self, session: aiohttp.ClientSession, max_redirects: int ):

        self.session = session
        self.max_redirects = max_redirects

    async def resolve(self, url: str) -> RedirectResult:
        try:
            async with self.session.get(
                url,
                allow_redirects=True,
                max_redirects=self.max_redirects,
            ) as response:

                history = response.history or []

                chain = [r.url.human_repr() for r in history] + [response.url.human_repr()]
                statuses = [r.status for r in history] + [response.status]

                return RedirectResult(
                    original_url=url,
                    chain=chain,
                    status_codes=statuses,
                    final_url=response.url.human_repr(),
                    final_status=response.status,
                    redirect_count=len(chain) - 1,
                    redirected=len(chain) > 1,
                )

        except aiohttp.TooManyRedirects:
            return RedirectResult(
                original_url=url,
                chain=[],
                status_codes=[],
                final_url="",
                final_status=0,
                redirect_count=self.max_redirects,
                redirected=True,
            )

        except asyncio.TimeoutError:
            return RedirectResult(
                original_url=url,
                chain=[],
                status_codes=[],
                final_url="",
                final_status=0,
                redirect_count=0,
                redirected=False,
            )

        except aiohttp.ClientError:
            return RedirectResult(
                original_url=url,
                chain=[],
                status_codes=[],
                final_url="",
                final_status=0,
                redirect_count=0,
                redirected=False,
            )