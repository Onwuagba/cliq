import logging

from celery import Task

from shortlink.celery import app
from common.utilities.mail.send_mail import send_mail_now

logger = logging.getLogger("app")


class RetryableTask(Task):
    autoretry_for = (Exception,)
    retry_backoff = True  # Enable exponential backoff
    retry_delay = 5  # Initial delay in seconds (5 minutes)
    retry_kwargs = {"max_retries": 5}


@app.task(base=RetryableTask)
def send_email_confirmation_mail(email_content, context):
    logger.info(
        "KENE-CELERY: account confirmation to recipient: "
        + f"{email_content.get('recipient')}"
    )
    _, res = send_mail_now(email_content, context)
    print(res)
    if not res:
        raise Exception()
    logger.info(
        f"Successfully sent account confirmation to recipient: {email_content['recipient']}",
    )


@app.task()
def send_notif_email(email_content, context):
    logger.info(
        "KENE-CELERY: mail to recipient: " + f"{email_content.get('recipient')}"
    )
    return send_mail_now(email_content, context)
