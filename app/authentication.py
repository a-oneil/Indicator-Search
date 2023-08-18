import os
import binascii
import base64
import json
from functools import wraps
from fastapi import Request, Header

from .exceptions import AuthenticationException
from .utils import b64_add_padding
from .models import User_Accounts


def auth_api_key(request, db):
    api_key = User_Accounts.get_user_by_api_key(request.api_key, db)
    if not api_key:
        raise AuthenticationException("Invalid API key")


def requires_auth(required=True, auth_header: str = Header(None)):
    # Import here to prevent circular imports
    from .models import Sessions

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                if not auth_header:
                    raise AuthenticationException(
                        "Authorization header missing from request"
                    )
                print(auth_header)
                # Header format: 'Authorization: Bearer <JWT>'
                parts = auth_header.split()
                if len(parts) != 2:
                    raise AuthenticationException("Header is incorrectly formatted")

                auth_token = parts[1]
            except AuthenticationException as e:
                if not required:
                    return func(*args, **kwargs)

                else:
                    raise e

            try:
                # Validate JWT segments
                _, _, _, _ = parse_jwt_segments(auth_token)
            except ValueError:
                # Not enough segments in the JWT, it is invalid
                raise AuthenticationException("Invalid JWT: Not enough segments")

            # Decode JWT and get user ID
            session = Sessions.validate_auth_token(auth_token)
            if not session:
                # This would only happen if the user was deleted and the session data was not
                # In that case, return a 401 error cause the authentication details are invalid
                raise AuthenticationException("This user no longer exists")

            # Set authenticated user
            Request.user_session = session

            # Pass auth token to endpoint function
            return func(*args, **kwargs)

        return wrapper

    return decorator


def parse_jwt_segments(jwt):
    try:
        # Validate JWT segments
        signing_input, crypto_segment = jwt.rsplit(".", 1)
        header_segment, payload_segment = signing_input.split(".", 1)
    except ValueError:
        # Not enough segments in the JWT, it is invalid
        return None

    return (header_segment, payload_segment, signing_input, crypto_segment)


def get_jwt_payload(jwt):
    try:
        (
            header_segment,
            payload_segment,
            signing_input,
            crypto_segment,
        ) = parse_jwt_segments(jwt)
    except ValueError:
        # Not enough segments in the JWT, it is invalid
        raise AuthenticationException("Invalid JWT: Not enough segments")

    # GET HEADER JSON
    """
    try:
        header_data = base64.b64decode(header_segment)
    except (TypeError, binascii.Error):
        # Invalid header segment (invalid base64 string)
        return None

    try:
        header = json.loads(header_data.decode('utf-8'))
    except ValueError as e:
        # Invalid header string
        return None
    """

    # GET PAYLOAD JSON

    try:
        payload_segment = b64_add_padding(payload_segment)
        payload_data = base64.b64decode(payload_segment)
    except (TypeError, binascii.Error):
        # Invalid payload segment (invalid base64 string)
        raise AuthenticationException("Invalid payload segment")

    try:
        payload = json.loads(payload_data.decode("utf-8"))
    except ValueError as e:
        # Invalid payload string
        raise AuthenticationException("Invalid payload string")

    # GET SIGNATURE
    # NOTE: probably don't need this
    """
    try:
        signature = base64.b64decode(crypto_segment)
    except (TypeError, binascii.Error):
        # Invalid signature segment (invalid base64 string)
        return None
    """

    return payload
    # return (header, payload, signing_input, crypto_segment)=
