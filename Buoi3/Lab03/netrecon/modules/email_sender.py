import smtplib
from email.message import EmailMessage
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv

load_dotenv()

def send_email(receiver_email, subject, body, smtp_user, smtp_pass):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = receiver_email
    msg.set_content(body)
    
    try:
        smtp = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        smtp.login(smtp_user, smtp_pass)
        smtp.send_message(msg)
        smtp.quit()
        print(f"[+] Email sent to {receiver_email}")
    except Exception as e:
        print(f"[-] Email failed: {e}")
