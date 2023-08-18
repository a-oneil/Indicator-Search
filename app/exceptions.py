from fastapi import HTTPException, status


class AuthorizationException(HTTPException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Unauthorized"
    headers = {"WWW-Authenticate": "Bearer"}

    def __init__(self, detail=None):
        if detail:
            self.detail = detail
        super().__init__(
            status_code=self.status_code, detail=self.detail, headers=self.headers
        )


class AuthenticationException(HTTPException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Unauthorized"
    headers = {"WWW-Authenticate": "Bearer"}

    def __init__(self, detail=None):
        if detail:
            self.detail = detail
        super().__init__(
            status_code=self.status_code, detail=self.detail, headers=self.headers
        )
