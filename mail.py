"""SMTP mail delivery for registration codes and admin tests. Standard library only."""
import smtplib
import ssl
from email.mime.text import MIMEText
from email.utils import formataddr


def configured(cfg):
    return bool(cfg['smtp_host'] and cfg['smtp_from'])


def send(cfg, to, subject, body):
    """Send a plain-text mail over SMTPS (465) or STARTTLS (other ports)."""
    if not configured(cfg):
        raise RuntimeError('Email service is not configured')
    port = cfg['smtp_port'] or 465
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = subject
    msg['From'] = formataddr(('LTZY', cfg['smtp_from']))
    msg['To'] = to
    timeout = 10
    if port == 465:
        server = smtplib.SMTP_SSL(cfg['smtp_host'], port, timeout=timeout,
                                  context=ssl.create_default_context())
    else:
        server = smtplib.SMTP(cfg['smtp_host'], port, timeout=timeout)
        try:
            server.starttls(context=ssl.create_default_context())
        except smtplib.SMTPNotSupportedError:
            pass  # Local relays without TLS are acceptable for private deployments.
    try:
        if cfg['smtp_user']:
            server.login(cfg['smtp_user'], cfg['smtp_pass'])
        server.sendmail(cfg['smtp_from'], [to], msg.as_string())
    finally:
        try:
            server.quit()
        except OSError:
            # Teardown must never mask the delivery error the caller needs to see.
            pass
