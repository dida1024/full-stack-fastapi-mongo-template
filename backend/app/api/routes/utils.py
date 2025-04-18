from fastapi import APIRouter, Depends
from pydantic.networks import EmailStr

from app.api.deps import get_current_active_superuser
from app.models import MessageResponse
from app.models.response import ApiResponse
from app.utils.email_helper import generate_test_email, send_email

router = APIRouter(prefix="/utils", tags=["utils"])


@router.post(
    "/test-email/",
    dependencies=[Depends(get_current_active_superuser)],
    status_code=201,
    response_model=ApiResponse[None],
)
def test_email(email_to: EmailStr) -> ApiResponse:
    """
    Test emails.
    """
    email_data = generate_test_email(email_to=email_to)
    send_email(
        email_to=email_to,
        subject=email_data.subject,
        html_content=email_data.html_content,
    )
    return ApiResponse.success_response(
        message="测试邮件已发送",
        code=201
    )


@router.get("/health-check/", response_model=ApiResponse[bool])
async def health_check() -> ApiResponse:
    return ApiResponse.success_response(
        data=True,
        message="服务正常"
    )
