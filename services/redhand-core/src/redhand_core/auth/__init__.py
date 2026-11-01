"""Authentication helpers for redhand-core."""


def bearer_token(authorization: str | None) -> str | None:
    """Returns the token from an `Authorization: Bearer <token>` header, else None.

    The scheme is required (case-insensitive per RFC 7235); a bare token is rejected so
    credentials are only ever accepted in the one documented form.
    """
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or " " in token:
        return None
    return token
