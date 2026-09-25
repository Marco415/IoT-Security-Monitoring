import httpx

from .config import settings


class OllamaClient:

    def __init__(self):

        self.url = (
            f"{settings.ollama_url.rstrip('/')}"
            "/api/generate"
        )

    async def generate(
        self,
        prompt: str
    ) -> str:

        payload = {
            "model": settings.ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1
            }
        }

        async with httpx.AsyncClient(
            timeout=settings.ollama_timeout
        ) as client:

            response = await client.post(
                self.url,
                json=payload
            )

            response.raise_for_status()

            data = response.json()

            return data.get(
                "response",
                ""
            ).strip()


ollama_client = OllamaClient()