"""API Routes - Authentication"""
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User, UserRole
from app.schemas.user import Token, UserCreate
from app.utils.auth import verify_password, create_access_token, get_password_hash
from app.config import settings

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/login", response_model=Token)
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Login to get an access token.
    
    **Note for Swagger UI:** 
    - Enter `username` and `password`.
    - **Ignore** `client_id` and `client_secret` (leave them empty).
    """
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role.value}, expires_delta=access_token_expires
    )
    
    # Set HttpOnly Cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=True, # Production (HTTPS)
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/register", response_model=Token)
async def register(response: Response, user_data: UserCreate, db: Session = Depends(get_db)):
    """Public registration endpoint"""
    # Check existing user
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    # Create new user
    db_user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        role=UserRole.ANALYST, # Default role for new signups
        is_active=True
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Auto-login (create token)
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.username, "role": db_user.role.value}, expires_delta=access_token_expires
    )
    
    # Set HttpOnly Cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=True, # Production
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/logout")
async def logout(response: Response):
    """Logout and clear cookie"""
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}
