"""Who may ask (D127: Meru's machine-to-machine standard, the way Thoth checks its callers).

felt-core sends an Authentik access token (client credentials, 10 minutes) as a Bearer token. drive-rag accepts it
only if the security standard's section 5 holds - Authentik's issuer, drive-rag's own audience, an allowed algorithm
and a key from Authentik's JWKS, within expiry / not-before (small leeway), required claims present - and the token
grants ``drive-rag.ask`` (Authentik fills the claim from the groups that list the caller, blueprint drive-rag.yaml).

Off unless DRIVE_RAG_AUTH_AUDIENCE is set: compose's drive-rag keeps its Felt-cert check alone until it's retired.

Revocation model: local validation until expiry; a caller taken out of its group stops within the token lifetime +
leeway.
"""

import logging
from functools import cache
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger(__name__)

ASK = "drive-rag.ask"


class AuthSettings(BaseSettings):
    """What the token check reads from DRIVE_RAG_AUTH_* - all empty means off."""

    model_config = SettingsConfigDict(env_prefix="DRIVE_RAG_AUTH_", frozen=True)

    audience: str = ""  # drive-rag
    issuer: str = ""  # https://auth.clockmost.com/application/o/drive-rag/
    jwks_url: str = ""  # https://auth.clockmost.com/application/o/drive-rag/jwks/
    algorithms: list[str] = ["RS256", "ES256"]
    leeway_seconds: int = 30  # clock tolerance - counts toward the revocation window
    permissions_claim: str = "drive_rag_permissions"
    name_claim: str = "preferred_username"

    @model_validator(mode="after")
    def _complete(self) -> "AuthSettings":
        if self.audience and not (self.issuer and self.jwks_url):
            raise ValueError(
                "DRIVE_RAG_AUTH_AUDIENCE is set: DRIVE_RAG_AUTH_ISSUER and _JWKS_URL are required too"
            )
        return self

    @property
    def enabled(self) -> bool:
        return bool(self.audience)


class UnauthenticatedError(Exception):
    """No token, or one drive-rag doesn't accept - the reason is logged, never sent back."""


class Verifier(BaseModel):
    """Accepts or refuses tokens."""

    model_config = ConfigDict(frozen=True)

    settings: AuthSettings
    keys: Any  # Authentik's JWKS, fetched and cached; tests hand in a key source of their own

    def verify(self, token: str) -> str:
        """The caller's name; raises if the token isn't accepted or doesn't grant ``drive-rag.ask``."""
        s = self.settings
        try:
            key = self.keys.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=s.algorithms,
                issuer=s.issuer,
                audience=s.audience,
                leeway=s.leeway_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except (jwt.PyJWTError, jwt.PyJWKClientError) as e:
            raise UnauthenticatedError(str(e)) from e
        raw = claims.get(s.permissions_claim, "")
        permissions = set(raw.split() if isinstance(raw, str) else raw)
        name = str(claims.get(s.name_claim) or claims["sub"])
        if ASK not in permissions:
            raise UnauthenticatedError(f"{name} holds no {ASK}")
        return name


@cache
def get_verifier() -> Verifier | None:
    """The verifier, or None when the check is off. Built once: the JWKS client keeps its keys for 5 minutes."""
    settings = AuthSettings()
    if not settings.enabled:
        return None
    return Verifier(
        settings=settings,
        keys=jwt.PyJWKClient(settings.jwks_url, cache_keys=True, lifespan=300),
    )


bearer = HTTPBearer(
    auto_error=False, description="An Authentik access token (client credentials)."
)
_CHALLENGE = {"WWW-Authenticate": "Bearer"}


def require_caller(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    verifier: Annotated[Verifier | None, Depends(get_verifier)],
) -> str | None:
    """Who is asking (None when the check is off), or a 401 with a Bearer challenge.

    A plain ``def``: FastAPI runs it in its thread pool, so a JWKS fetch never blocks the event loop."""
    if verifier is None:
        return None
    if credentials is None:
        raise HTTPException(401, "a bearer token is required", headers=_CHALLENGE)
    try:
        return verifier.verify(credentials.credentials)
    except UnauthenticatedError as e:
        log.warning("refused a token: %s", e)
        raise HTTPException(401, "the token isn't accepted", headers=_CHALLENGE) from e
