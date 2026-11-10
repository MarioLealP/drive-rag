"""server.auth: the Authentik token check (D127), against tokens signed with a test key."""

import time
from typing import Annotated

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from server import auth

ISSUER = "https://auth.example/application/o/drive-rag/"
SETTINGS = auth.AuthSettings(
    audience="drive-rag", issuer=ISSUER, jwks_url="https://auth.example/jwks/"
)


class _Key:
    def __init__(self, key):
        self.key = key


class _Keys:
    """Stands in for PyJWKClient: hands out the one public key."""

    def __init__(self, public):
        self.public = public

    def get_signing_key_from_jwt(self, token):
        return _Key(self.public)


@pytest.fixture(scope="module")
def signer():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def verifier(signer):
    return auth.Verifier(settings=SETTINGS, keys=_Keys(signer.public_key()))


def _token(signer, **over):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": "drive-rag",
        "sub": "hashed",
        "iat": now,
        "exp": now + 600,
        "preferred_username": "k8s-felt-core-felt-core",
        "drive_rag_permissions": ["drive-rag.ask"],
    } | over
    return jwt.encode(
        {k: v for k, v in claims.items() if v is not None}, signer, algorithm="RS256"
    )


def test_felt_core_accepted(signer, verifier):
    assert verifier.verify(_token(signer)) == "k8s-felt-core-felt-core"


@pytest.mark.parametrize(
    "over",
    [
        {"aud": "thoth"},  # another app's token
        {"iss": "https://auth.example/application/o/thoth/"},
        {"exp": int(time.time()) - 120},  # past the 30 s leeway
        {"drive_rag_permissions": []},  # a valid token that grants nothing here
        {"drive_rag_permissions": None},
        {"exp": None},  # required claims
    ],
)
def test_refused(signer, verifier, over):
    with pytest.raises(auth.UnauthenticatedError):
        verifier.verify(_token(signer, **over))


def test_other_key_refused(verifier):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(auth.UnauthenticatedError):
        verifier.verify(_token(other))


def test_none_algorithm_refused(verifier):
    token = jwt.encode({"iss": ISSUER, "aud": "drive-rag"}, None, algorithm="none")
    with pytest.raises(auth.UnauthenticatedError):
        verifier.verify(token)


def test_audience_needs_issuer_and_jwks():
    with pytest.raises(ValueError):
        auth.AuthSettings(audience="drive-rag")


def _client(verifier):
    app = FastAPI()

    @app.post("/ask")
    def ask(caller: Annotated[str | None, Depends(auth.require_caller)]):
        return {"caller": caller}

    app.dependency_overrides[auth.get_verifier] = lambda: verifier
    return TestClient(app)


def test_route_needs_a_token(signer, verifier):
    c = _client(verifier)
    r = c.post("/ask")
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
    assert c.post("/ask", headers={"Authorization": "Bearer nope"}).status_code == 401
    ok = c.post("/ask", headers={"Authorization": f"Bearer {_token(signer)}"})
    assert ok.status_code == 200 and ok.json() == {"caller": "k8s-felt-core-felt-core"}


def test_off_lets_everyone_in():
    assert _client(None).post("/ask").json() == {"caller": None}
