
from jose import JWTError, jwt

from config import settings


def get_user_id_from_access_token(token: str) -> str:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )

        if payload.get("type") != "access":
            raise ValueError("Not an access token")

        user_id = payload.get("sub")

        if not user_id:
            raise ValueError("Missing user ID")

        return user_id

    except (JWTError, ValueError) as error:
        raise ValueError("Invalid access token") from error
