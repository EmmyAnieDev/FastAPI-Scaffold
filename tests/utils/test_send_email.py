from unittest.mock import AsyncMock, patch, Mock
import pytest
import logging
from app.api.utils.send_email import send_email

@pytest.mark.asyncio
async def test_send_email_failure(caplog):
    """
    Test that send_email logs an error when sending fails.
    """
    recipients = ["fail@example.com"]
    template_name = "welcome.html"
    subject = "Fail Test"
    context = {"name": "John"}

    with patch("app.api.utils.send_email.FastMail") as mock_fastmail, \
         patch("main.email_templates.get_template") as mock_get_template:

        mock_template = Mock()
        mock_template.render.return_value = "<p>Hello John</p>"
        mock_get_template.return_value = mock_template

        mock_instance = mock_fastmail.return_value
        mock_instance.send_message = AsyncMock(side_effect=Exception("SMTP error"))

        caplog.set_level(logging.ERROR)

        with pytest.raises(Exception) as exc_info:
            await send_email(recipients, template_name, subject, context)

        assert str(exc_info.value) == "SMTP error"
        assert any("Failed to send email" in record.message for record in caplog.records)
