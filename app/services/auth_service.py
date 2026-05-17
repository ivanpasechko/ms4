from datetime import datetime, timedelta
from typing import Optional, List
from sqlmodel import Session, select
from fastapi import HTTPException, status
from app.models.user import User, UserAuth, TokenResponse
from app.models.history import LoginHistory
from app.core.security import hash_password, verify_password, create_token, decode_token
from app.core.config import settings
from app.core.redis_config import redis_client

class AuthService:
    @staticmethod
    def register_user(session: Session, user_data: UserAuth) -> User:
        statement = select(User).where(User.email == user_data.email)
        existing_user = session.exec(statement).first()
        if existing_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
        
        db_user = User(
            email=user_data.email,
            hashed_password=hash_password(user_data.password)
        )
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        return db_user

    @staticmethod
    def authenticate_user(session: Session, user_data: UserAuth, user_agent: Optional[str]) -> TokenResponse:
        statement = select(User).where(User.email == user_data.email)
        user = session.exec(statement).first()
        if not user or not verify_password(user_data.password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        
        # Логируем историю входа
        history_entry = LoginHistory(user_id=user.id, user_agent=user_agent)
        session.add(history_entry)
        session.commit()

        # Генерируем токены
        access_token = create_token({"sub": str(user.id), "type": "access"}, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
        refresh_token = create_token({"sub": str(user.id), "type": "refresh"}, timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
        
        return TokenResponse(access_token=access_token, refresh_token=refresh_token)

    @staticmethod
    def refresh_access_token(refresh_token: str) -> dict:
        payload = decode_token(refresh_token)
        if not payload or payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")
        
        user_id = payload.get("sub")
        new_access_token = create_token({"sub": user_id, "type": "access"}, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
        return {"access_token": new_access_token}

    @staticmethod
    def update_user_profile(session: Session, user_id: int, update_data: UserAuth) -> User:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Проверяем, не занят ли новый email кем-то другим
        if user.email != update_data.email:
            email_check = session.exec(select(User).where(User.email == update_data.email)).first()
            if email_check:
                raise HTTPException(status_code=400, detail="Email already in use")
        
        user.email = update_data.email
        user.hashed_password = hash_password(update_data.password)
        session.add(user)
        session.commit()
        session.refresh(user)
        return user

    @staticmethod
    def get_login_history(session: Session, user_id: int) -> List[LoginHistory]:
        return session.exec(select(LoginHistory).where(LoginHistory.user_id == user_id)).all()

    @staticmethod
    def blacklist_token(token: str, payload: dict) -> None:
        # Доп. задание: вычисляем оставшийся TTL токена и пишем в Redis
        exp = payload.get("exp")
        now = datetime.utcnow().timestamp()
        ttl = int(exp - now)
        if ttl > 0:
            redis_client.setex(f"blacklist:{token}", ttl, "true")