from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
import logging

from app import crud
from app.api.deps import CurrentUser, CurrentSuperuser
from app.core import security
from app.core.config import settings
from app.core.security import get_password_hash
from app.models import MessageResponse, PasswordResetConfirm, Token, UserPublic
from app.models.response import ApiResponse
from app.utils.email_helper import (
    generate_reset_password_email,
    send_email,
)
from app.utils.token_helper import (
    generate_password_reset_token,
    verify_password_reset_token,
)
from app.exceptions.auth_exceptions import AuthFail,UserEmailOrPasswordFail
from app.exceptions.user_exceptions import UserNotFound,UserNotActive

logger = logging.getLogger(__name__)

router = APIRouter(tags=["login"])


@router.post("/login/access-token", response_model=ApiResponse[Token])
async def login_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests
    """
    logger.info(f"Login attempt for user: {form_data.username}")
    user = await crud.authenticate(
        email=form_data.username, password=form_data.password
    )
    if not user:
        logger.warning(f"Authentication failed for user: {form_data.username}")
        raise UserEmailOrPasswordFail
    elif not user.is_active:
        logger.warning(f"Inactive user attempt: {form_data.username}")
        raise UserNotActive
    
    logger.info(f"Creating access token for user: {user.id}")
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = security.create_access_token(
        user.id, expires_delta=access_token_expires
    )
    logger.info(f"Access token created successfully for user: {user.id}")
    return ApiResponse.success_response(
        data=Token(access_token=token),
        message="登录成功"
    )


@router.post("/login/test-token", response_model=ApiResponse[UserPublic])
async def test_token(current_user: CurrentUser) -> Any:
    """
    Test access token
    """
    return ApiResponse.success_response(data=current_user)


@router.post("/password-recovery/{email}", response_model=ApiResponse[None])
async def recover_password(email: str) -> Any:
    """
    Password Recovery
    """
    user = await crud.get_user_by_email(email=email)

    if not user:
        raise UserNotFound
    password_reset_token = generate_password_reset_token(email=email)
    email_data = generate_reset_password_email(
        email_to=user.email, email=email, token=password_reset_token
    )
    send_email(
        email_to=user.email,
        subject=email_data.subject,
        html_content=email_data.html_content,
    )
    return ApiResponse.success_response(message="密码重置邮件已发送")


@router.post("/reset-password/", response_model=ApiResponse[None])
async def reset_password(body: PasswordResetConfirm) -> Any:
    """
    Reset password
    """
    email = verify_password_reset_token(token=body.token)
    if not email:
        raise AuthFail
    user = await crud.get_user_by_email(email=email)
    if not user:
        raise UserNotFound
    elif not user.is_active:
        raise UserNotActive
    
    user.hashed_password = get_password_hash(password=body.new_password)
    await user.save()
    return ApiResponse.success_response(message="密码更新成功")


@router.post(
    "/password-recovery-html-content/{email}",
    dependencies=[Depends(CurrentSuperuser)],
    response_class=HTMLResponse,
)
async def recover_password_html_content(email: str) -> Any:
    """
    HTML Content for Password Recovery
    """
    user = await crud.get_user_by_email(email=email)

    if not user:
        raise UserNotFound
    password_reset_token = generate_password_reset_token(email=email)
    email_data = generate_reset_password_email(
        email_to=user.email, email=email, token=password_reset_token
    )

    return HTMLResponse(
        content=email_data.html_content, headers={"subject:": email_data.subject}
    )
