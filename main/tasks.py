import logging

from shortlink.celery import app
from common.utilities.mail.send_mail import send_mail_now

logger = logging.getLogger("app")

@app.task()
def send_email_confirmation_mail(email_content, context):
    logger.info(
        "Successfully entered celery to send account confirmation to recipient: "
        + f"{email_content.get('recipient')}"
    )
    return send_mail_now(email_content, context)


@app.task()
def send_notif_email(email_content, context):
    logger.info(
        "Successfully entered celery to send mail to recipient: "
        + f"{email_content.get('recipient')}"
    )
    return send_mail_now(email_content, context)