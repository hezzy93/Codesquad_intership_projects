from fastapi import APIRouter, Depends, HTTPException, status, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from database import get_db
from models.user import User
from schemas.user import UserCreate, UserResponse
from services.auth import hash_password
from models.refresh_token import RefreshToken
from schemas.auth import LoginRequest, TokenResponse, RefreshRequest
from services.auth import verify_password
from services.token import create_access_token, create_refresh_token
from services.security import get_user_id_from_access_token
from config import settings
import hashlib

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)
bearer_scheme = HTTPBearer()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
):
    existing_user = (
        db.query(User)
        .filter(
            (User.email == user_data.email)
            | (User.username == user_data.username)
        )
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists",
        )

    hashed_password = hash_password(user_data.password)

    new_user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=hashed_password,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user



@router.post("/login", response_model=TokenResponse)
def login_user(
    login_data: LoginRequest,
    db: Session = Depends(get_db),
):
    user = (
        db.query(User)
        .filter(User.email == login_data.email)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    password_is_valid = verify_password(
        login_data.password,
        user.password_hash,
    )

    if not password_is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    access_token = create_access_token(str(user.id))

    refresh_token, token_hash = create_refresh_token()

    expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )

    token_record = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
    )

    db.add(token_record)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh", response_model=TokenResponse)
def refresh_access_token(
    refresh_data: RefreshRequest,
    db: Session = Depends(get_db),
):
    # 1. Hash the refresh token received from the client
    token_hash = hashlib.sha256(
        refresh_data.refresh_token.encode("utf-8")
    ).hexdigest()

    # 2. Find the matching token record in the database
    stored_token = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_hash == token_hash)
        .first()
    )

    # 3. Reject unknown tokens
    if stored_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    now = datetime.now(timezone.utc)

    # 4. Reject expired or revoked tokens
    if (
        stored_token.revoked_at is not None
        or stored_token.expires_at <= now
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    # 5. Confirm that the user still exists
    user = (
        db.query(User)
        .filter(User.id == stored_token.user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    # 6. Revoke the old token atomically.
    # This also helps prevent two requests from reusing the same token.
    updated_rows = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.id == stored_token.id,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > now,
        )
        .update(
            {RefreshToken.revoked_at: now},
            synchronize_session=False,
        )
    )

    if updated_rows != 1:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    try:
        # 7. Create a new access token and refresh token
        new_access_token = create_access_token(str(user.id))

        new_refresh_token, new_token_hash = create_refresh_token()

        new_expiry = now + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )

        # 8. Store only the hash of the new refresh token
        new_token_record = RefreshToken(
            user_id=user.id,
            token_hash=new_token_hash,
            expires_at=new_expiry,
        )

        db.add(new_token_record)
        db.commit()

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to refresh tokens",
        )

    # 9. Return the new token pair
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }



@router.get("/me", response_model=UserResponse)
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    db: Session = Depends(get_db),
):
    token = credentials.credentials

    try:
        user_id = get_user_id_from_access_token(token)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


@router.post("/logout")
def logout(
    refresh_data: RefreshRequest,
    db: Session = Depends(get_db),
):
    token_hash = hashlib.sha256(
        refresh_data.refresh_token.encode("utf-8")
    ).hexdigest()

    stored_token = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_hash == token_hash)
        .first()
    )

    if stored_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if stored_token.revoked_at is None:
        stored_token.revoked_at = datetime.now(timezone.utc)
        db.commit()

    return {"message": "Logged out successfully"}

@router.get("/users")
def get_all_users(db: Session = Depends(get_db)):
    users = db.query(User).all()

    return users