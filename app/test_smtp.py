import smtplib
import os
from email.message import EmailMessage
import ssl

# Try to load .env file if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("Loaded .env file")
except ImportError:
    print("python-dotenv not installed, relying on environment variables")

def test_smtp():
    # Configuration
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_mail = os.getenv("SMTP_MAIL")
    smtp_password = os.getenv("SMTP_PASSWORD")
    
    if not smtp_mail or not smtp_password:
        print("Error: SMTP_MAIL and SMTP_PASSWORD environment variables must be set.")
        print("You can set them in a .env file or export them in your shell.")
        return

    print(f"Testing SMTP connection to {smtp_server}:{smtp_port}...")
    print(f"User: {smtp_mail}")

    try:
        # Create a secure SSL context
        context = ssl.create_default_context()

        # Connect to the server
        print("Connecting...")
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo() # Can be omitted
        server.starttls(context=context) # Secure the connection
        server.ehlo() # Can be omitted
        
        # Login
        print("Logging in...")
        server.login(smtp_mail, smtp_password)
        print("Login successful!")

        # Send a test email
        msg = EmailMessage()
        msg.set_content("This is a test email from your FlaskBlog SMTP configuration test script.")
        msg['Subject'] = 'SMTP Test Email'
        msg['From'] = smtp_mail
        msg['To'] = smtp_mail # Send to self

        print("Sending test email...")
        server.send_message(msg)
        print(f"Test email sent successfully to {smtp_mail}!")

        server.quit()

    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nTroubleshooting tips:")
        print("1. Check if your email and password are correct.")
        print("2. If using Gmail, ensure you are using an 'App Password', not your login password.")
        print("3. Check if your firewall or antivirus is blocking the connection.")

if __name__ == "__main__":
    test_smtp()
