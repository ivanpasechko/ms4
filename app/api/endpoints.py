from typing import List
from fastapi import APIRouter, Depends, Header, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlmodel import Session
from app.core.database import get_session
from app.core.security import decode_token
from app.api.deps import get_current_user, security_scheme
from app.models.user import User, UserAuth, TokenResponse, RefreshRequest
from app.models.history import LoginHistoryRead
from app.services.auth_service import AuthService

router = APIRouter()

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(user_data: UserAuth, session: Session = Depends(get_session)):
    user = AuthService.register_user(session, user_data)
    return {"id": user.id, "email": user.email, "status": "registered"}

@router.post("/login", response_model=TokenResponse)
def login(user_data: UserAuth, request: Request, session: Session = Depends(get_session), user_agent: str = Header(None)):
    return AuthService.authenticate_user(session, user_data, user_agent)

@router.post("/refresh")
def refresh_token(body: RefreshRequest):
    return AuthService.refresh_access_token(body.refresh_token)

@router.put("/user/update")
def update_user(update_data: UserAuth, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    user = AuthService.update_user_profile(session, current_user.id, update_data)
    return {"id": user.id, "email": user.email, "status": "updated"}

@router.get("/user/history", response_model=List[LoginHistoryRead])
def get_history(current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    return AuthService.get_login_history(session, current_user.id)

@router.post("/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)):
    token = credentials.credentials
    payload = decode_token(token)
    if payload:
        AuthService.blacklist_token(token, payload)
    return {"detail": "Successfully logged out"}