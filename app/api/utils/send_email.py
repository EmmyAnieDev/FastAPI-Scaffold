from typing import Optional
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from config import settings
from premailer import transform
import logging

logger = logging.getLogger(__name__)


async def send_email(
        recipients: list[str],
        template_name: str,
        subject: str,
        context: Optional[dict] = None
) -> None:
    """
    Send an email using the specified template and context.

    Args:
        recipients: Email address of the recipients.
        template_name: Name of the email template.
        subject: Subject of the email.
        context: Optional context dictionary to render the template.
    """

    from main import email_templates

    # Ensure context is a dictionary, even if None is passed
    if context is None:
        context = {}

    email_conf = ConnectionConfig(
        MAIL_USERNAME=settings.MAIL_USERNAME,
        MAIL_PASSWORD=settings.MAIL_PASSWORD,
        MAIL_FROM=settings.MAIL_FROM,
        MAIL_PORT=settings.MAIL_PORT,
        MAIL_SERVER=settings.MAIL_SERVER,
        USE_CREDENTIALS=True,
        VALIDATE_CERTS=True,
        MAIL_STARTTLS=False,
        MAIL_SSL_TLS=True,
        MAIL_FROM_NAME='---',
    )

    try:
        # Render the email template with the provided context.
        html = email_templates.get_template(template_name).render(context)
        message = MessageSchema(
            subject=subject,
            recipients=recipients,
            subtype=MessageType.html,
            body=transform(html)
        )
        fm = FastMail(email_conf)
        await fm.send_message(message)
    except Exception as e:
        logger.error(f"Failed to send email to {recipients}: {str(e)}")
        raise e