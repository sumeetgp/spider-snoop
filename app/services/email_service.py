"""Email service using SMTP2GO API"""
import os
import requests
from typing import Optional
from app.config import settings
import logging

logger = logging.getLogger(__name__)

class EmailService:
    """Email service for sending emails via SMTP2GO"""
    
    def __init__(self):
        self.api_key = os.getenv('SMTP2GO_API_KEY')
        self.api_url = "https://api.smtp2go.com/v3/email/send"
        self.sender_email = "noreply@spidercob.com"
        self.sender_name = "SpiderCob Security"
        
    def send_email(self, to_email: str, subject: str, html_body: str, text_body: Optional[str] = None) -> bool:
        """
        Send an email using SMTP2GO API
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_body: HTML email body
            text_body: Plain text email body (optional)
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        if not self.api_key:
            logger.warning("SMTP2GO_API_KEY not configured. Email not sent.")
            return False
            
        payload = {
            "api_key": self.api_key,
            "to": [to_email],
            "sender": f"{self.sender_name} <{self.sender_email}>",
            "subject": subject,
            "html_body": html_body,
        }
        
        if text_body:
            payload["text_body"] = text_body
            
        try:
            response = requests.post(self.api_url, json=payload, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            
            if result.get('data', {}).get('succeeded', 0) > 0:
                logger.info(f"Email sent successfully to {to_email}")
                return True
            else:
                logger.error(f"Failed to send email to {to_email}: {result}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending email via SMTP2GO: {e}")
            return False
    
    def send_password_reset_email(self, to_email: str, reset_url: str, username: str) -> bool:
        """
        Send password reset email
        
        Args:
            to_email: User's email address
            reset_url: Password reset URL with token
            username: User's username
            
        Returns:
            bool: True if email sent successfully
        """
        subject = "🕸️ SpiderCob - Password Reset Request"
        
        html_body = self._get_password_reset_template(reset_url, username)
        text_body = self._get_password_reset_text(reset_url, username)
        
        return self.send_email(to_email, subject, html_body, text_body)
    
    def _get_password_reset_template(self, reset_url: str, username: str) -> str:
        """Generate HTML email template for password reset"""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset - SpiderCob</title>
</head>
<body style="margin: 0; padding: 0; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background-color: #0D1117;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #0D1117; padding: 40px 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #161B22; border: 1px solid #30363d; border-radius: 12px; overflow: hidden;">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 40px 40px 20px; text-align: center; background: linear-gradient(135deg, #161B22 0%, #0D1117 100%);">
                            <h1 style="margin: 0; font-size: 32px; font-weight: 900; color: #ffffff; letter-spacing: -1px;">
                                🕸️ Spider<span style="color: #88FFFF;">Cob</span>
                            </h1>
                            <p style="margin: 10px 0 0; font-size: 12px; color: #8B949E; font-family: 'JetBrains Mono', monospace; letter-spacing: 2px;">
                                SECURITY PLATFORM
                            </p>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px;">
                            <h2 style="margin: 0 0 20px; font-size: 20px; color: #C9D1D9; font-weight: 700;">
                                Password Reset Request
                            </h2>
                            
                            <p style="margin: 0 0 20px; font-size: 15px; line-height: 1.6; color: #8B949E;">
                                Hello <strong style="color: #C9D1D9;">{username}</strong>,
                            </p>
                            
                            <p style="margin: 0 0 20px; font-size: 15px; line-height: 1.6; color: #8B949E;">
                                We received a request to reset your password for your SpiderCob account. Click the button below to create a new password:
                            </p>
                            
                            <!-- CTA Button -->
                            <table width="100%" cellpadding="0" cellspacing="0" style="margin: 30px 0;">
                                <tr>
                                    <td align="center">
                                        <a href="{reset_url}" style="display: inline-block; padding: 16px 40px; background-color: #88FFFF; color: #0D1117; text-decoration: none; font-weight: 700; font-size: 14px; border-radius: 6px; letter-spacing: 0.5px; box-shadow: 0 0 20px rgba(136, 255, 255, 0.3);">
                                            RESET PASSWORD
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            
                            <p style="margin: 20px 0; font-size: 13px; line-height: 1.6; color: #8B949E;">
                                Or copy and paste this link into your browser:
                            </p>
                            
                            <div style="padding: 12px; background-color: #0D1117; border: 1px solid #30363d; border-radius: 6px; margin: 10px 0 20px;">
                                <a href="{reset_url}" style="color: #88FFFF; text-decoration: none; font-size: 12px; word-break: break-all; font-family: 'JetBrains Mono', monospace;">
                                    {reset_url}
                                </a>
                            </div>
                            
                            <!-- Security Notice -->
                            <div style="margin: 30px 0; padding: 16px; background-color: #1C2128; border-left: 3px solid #F85149; border-radius: 6px;">
                                <p style="margin: 0; font-size: 13px; line-height: 1.6; color: #F85149; font-weight: 600;">
                                    ⚠️ Security Notice
                                </p>
                                <p style="margin: 8px 0 0; font-size: 13px; line-height: 1.6; color: #8B949E;">
                                    This link will expire in <strong style="color: #C9D1D9;">1 hour</strong>. If you didn't request this password reset, please ignore this email or contact our security team immediately.
                                </p>
                            </div>
                            
                            <p style="margin: 20px 0 0; font-size: 13px; line-height: 1.6; color: #8B949E;">
                                Best regards,<br>
                                <strong style="color: #C9D1D9;">The SpiderCob Security Team</strong>
                            </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 30px 40px; background-color: #0D1117; border-top: 1px solid #30363d; text-align: center;">
                            <p style="margin: 0 0 10px; font-size: 12px; color: #6E7681; font-family: 'JetBrains Mono', monospace;">
                                © 2026 SpiderCob Security Platform
                            </p>
                            <p style="margin: 0; font-size: 11px; color: #484F58;">
                                This is an automated message. Please do not reply to this email.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""
    
    def _get_password_reset_text(self, reset_url: str, username: str) -> str:
        """Generate plain text version of password reset email"""
        return f"""
SpiderCob - Password Reset Request

Hello {username},

We received a request to reset your password for your SpiderCob account.

To reset your password, click the link below or copy and paste it into your browser:

{reset_url}

SECURITY NOTICE:
This link will expire in 1 hour. If you didn't request this password reset, please ignore this email or contact our security team immediately.

Best regards,
The SpiderCob Security Team

---
© 2026 SpiderCob Security Platform
This is an automated message. Please do not reply to this email.
"""

# Singleton instance
email_service = EmailService()
