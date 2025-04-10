"""Email notification channel for the alert system."""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any
from ..alert_manager import NotificationChannel
import logging

class EmailChannel(NotificationChannel):
    """Email notification channel implementation."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the email channel.
        
        Args:
            config: Email configuration containing SMTP settings and recipients
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Required configuration fields
        self.smtp_host = config.get('smtp_host')
        self.smtp_port = config.get('smtp_port')
        self.smtp_username = config.get('smtp_username')
        self.smtp_password = config.get('smtp_password')
        self.from_address = config.get('from_address')
        self.recipients = config.get('recipients', [])
        self.use_tls = config.get('use_tls', True)

    def validate_config(self) -> bool:
        """Validate email channel configuration.
        
        Returns:
            bool: True if configuration is valid, False otherwise
        """
        required_fields = [
            'smtp_host',
            'smtp_port',
            'smtp_username',
            'smtp_password',
            'from_address',
            'recipients'
        ]
        
        for field in required_fields:
            if not getattr(self, field):
                self.logger.error(f"Missing required configuration field: {field}")
                return False
                
        if not isinstance(self.recipients, list) or not self.recipients:
            self.logger.error("Recipients must be a non-empty list")
            return False
            
        return True

    def format_alert_html(self, alert: Dict[str, Any]) -> str:
        """Format alert as HTML email content.
        
        Args:
            alert: Alert information dictionary
            
        Returns:
            str: Formatted HTML content
        """
        severity_colors = {
            'CRITICAL': '#FF0000',
            'HIGH': '#FF4500',
            'MEDIUM': '#FFA500',
            'LOW': '#FFD700',
            'INFO': '#4682B4'
        }
        
        color = severity_colors.get(alert['severity'], '#000000')
        
        html = f"""
        <html>
            <body>
                <h2>{alert['title']}</h2>
                <p><strong>Severity:</strong> <span style="color: {color}">{alert['severity']}</span></p>
                <p><strong>Source:</strong> {alert['source']}</p>
                <p><strong>Time:</strong> {alert['timestamp']}</p>
                <p><strong>Message:</strong></p>
                <p>{alert['message']}</p>
        """
        
        if alert['findings']:
            html += "<h3>Findings:</h3><ul>"
            for finding in alert['findings']:
                html += f"<li><strong>{finding.get('title', 'Untitled Finding')}</strong>"
                if 'description' in finding:
                    html += f"<br>{finding['description']}"
                html += "</li>"
            html += "</ul>"
            
        html += """
            </body>
        </html>
        """
        
        return html

    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send alert through email.
        
        Args:
            alert: Alert information dictionary
            
        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{alert['severity']}] {alert['title']}"
            msg['From'] = self.from_address
            msg['To'] = ', '.join(self.recipients)
            
            # Create HTML content
            html_content = self.format_alert_html(alert)
            msg.attach(MIMEText(html_content, 'html'))
            
            # Connect to SMTP server and send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
                
            self.logger.info(f"Alert email sent successfully to {len(self.recipients)} recipients")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send alert email: {str(e)}")
            return False 