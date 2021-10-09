"""Security methods for graphql"""

import logging

import time
from typing import Optional

from fastapi import HTTPException
from fastapi.security import HTTPBasic, HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Scope, Receive, Send
from starlette.websockets import WebSocket
from starlette_graphene3 import GraphQLApp

JWT_DECODE_KEY = "Change_me_please_please_please"
JWT_ALGORITHM = "HS256"

logger = logging.getLogger(__name__)

security = HTTPBasic()


def decode_jwt(token: str) -> Optional[dict]:
    try:
        decoded_token = jwt.decode(token, JWT_DECODE_KEY, algorithms=[JWT_ALGORITHM])
        return decoded_token if decoded_token["exp"] >= time.time() else None
    except Exception as exp:
        logger.error(exp)
        return None


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(
            JWTBearer, self
        ).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(
                    status_code=403, detail="Invalid authentication scheme."
                )
            if not JWTBearer.verify_jwt(credentials.credentials):
                raise HTTPException(
                    status_code=403, detail="Invalid token or expired token."
                )
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    @staticmethod
    async def validate_ws(headers):
        auth_header = headers.get("Authorization")
        if not auth_header or not isinstance(auth_header, str):
            raise HTTPException(status_code=403, detail="Invalid authorization code.")
        try:
            scheme, token = auth_header.split(" ")
        except ValueError:
            raise HTTPException(
                status_code=403, detail="Invalid authentication scheme."
            )
        if scheme != "Bearer":
            raise HTTPException(
                status_code=403, detail="Invalid authentication scheme."
            )
        if not JWTBearer.verify_jwt(token):
            raise HTTPException(
                status_code=403, detail="Invalid token or expired token."
            )
        return token

    @staticmethod
    def verify_jwt(jwtoken: str) -> bool:
        is_token_valid: bool = False

        payload = decode_jwt(jwtoken)
        if payload:
            is_token_valid = True
        return is_token_valid


class SecureGraphQLApp(GraphQLApp):
    """Class that inherits default starlette_graphene_3
    and adding security to all graphql requests
    """

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            request = Request(scope=scope, receive=receive)
            bearer = JWTBearer()
            await bearer(request=request)
            response: Optional[Response] = None
            if request.method == "POST":
                response = await self._handle_http_request(request)
            elif request.method == "GET":
                response = await self._get_on_get(request)
            if not response:
                response = Response(status_code=405)
            await response(scope, receive, send)

        elif scope["type"] == "websocket":
            headers = scope.get("headers")
            bearer = JWTBearer()
            await bearer.validate_ws(headers)
            websocket = WebSocket(scope=scope, receive=receive, send=send)
            await self._run_websocket_server(websocket)
        else:
            raise ValueError(f"Unsupported scope type: ${scope['type']}")
