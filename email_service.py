import smtplib
import os
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

def generate_verification_code() -> str:
  # Generate random 6 digit verification code
  return str(random.randint(100000, 999999))

def send_verification_email(to_email: str, code: str) -> bool:
  # Send verification through Gmail SMTP
  """ Required in .env:
      EMAIL_ADDRESS=yourgmail.gmail.com
      EMAIL_PASSWORD=your_email_password
  """
  try:
      msg = MIMEMultipart()
      msg["From"]    = EMAIL_ADDRESS
      msg["To"]      = to_email
      msg["Subject"] = "TALUS - Verify your email"

      body = f"""      
Your email verification code is:

    {code}

This code expires in 10 minutes. Please do not share it with anyone.

If you did not create a TALUS account, ignore this email.
      """
      msg.attach(MIMEText(body, "plain"))

      with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
          smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
          smtp.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())

      return True

  except Exception as e:
      print(f"Failed to send verification email: {e}")
      return False
