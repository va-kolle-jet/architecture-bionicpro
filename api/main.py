import os
import random
import string
import requests
import logging
from httpx import AsyncClient
import jwt
from jwt.exceptions import PyJWTError
from jwt.algorithms import RSAAlgorithm
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.cors import CORSMiddleware

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REPORT_ROLE = "prothetic_user"
APP_KEYCLOAK_URL = os.environ.get("APP_KEYCLOAK_URL", "http://localhost:8080")
APP_KEYCLOAK_REALM = os.environ.get("APP_KEYCLOAK_REALM", "reports-realm")
APP_KEYCLOAK_CERTS_URL = f"{APP_KEYCLOAK_URL}/realms/{APP_KEYCLOAK_REALM}/protocol/openid-connect/certs"

bearer = HTTPBearer()

async def load_public_key():
    async with AsyncClient() as client:
        logger.info(f"APP_KEYCLOAK_CERTS_URL: {APP_KEYCLOAK_CERTS_URL}")
        response = await client.get(APP_KEYCLOAK_CERTS_URL)
        if response.status_code != 200:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="missing keycloak keys")
        keys = response.json()
        logger.debug(f"keys: {keys}")
        # public_key = RSAAlgorithm.from_jwk(keys['keys'][1])
        public_key = RSAAlgorithm.from_jwk(keys['keys'][0])
        logger.debug(f"public_key: {public_key}")
        return public_key

async def get_current_user(token: HTTPAuthorizationCredentials = Depends(bearer)):

    public_key = await load_public_key()

    try:
        logger.debug(f"token.credentials: {token.credentials}")
        payload = jwt.decode(token.credentials, public_key, algorithms=['RS256'])
        logger.debug(f"payload: {payload}")
    except Exception as e:
        logger.error(f"str(e): {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    realm_access = payload.get("realm_access", {})
    logger.debug(f"realm_access: {realm_access}")
    roles = realm_access.get("roles", [])
    logger.info(f"roles: {roles}")
    if REPORT_ROLE not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"missing '{REPORT_ROLE}' role")

    return payload


def generate_random_string(length=10):
    """Генерирует случайную строку заданной длины."""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

async def generate_random_data(n, k):
    """Генерирует таблицу с n колонками и k строками."""
    data = []
    for _ in range(k):
        row = [generate_random_string() for _ in range(n)]
        data.append(row)
    return data

@app.get("/reports", dependencies=[Depends(get_current_user)])
async def get_reports():

    return await generate_random_data(10, 10)