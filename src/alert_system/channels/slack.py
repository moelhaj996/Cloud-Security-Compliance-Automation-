"""Slack notification channel for the alert system."""

import json
import requests
from typing import Dict, Any, List
from ..alert_manager import NotificationChannel
import logging

class SlackChannel(NotificationChannel):
    """Slack notification channel implementation."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the Slack channel.
        
        Args:
            config: Slack configuration containing webhook URL and channel settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Required configuration fields
        self.webhook_url = config.get('webhook_url')
        self.channel = config.get('channel')
        self.username = config.get('username', 'Security Alert Bot')
        self.icon_emoji = config.get('icon_emoji', ':warning:')

    def validate_config(self) -> bool:
        """Validate Slack channel configuration.
        
        Returns:
            bool: True if configuration is valid, False otherwise
        """
        if not self.webhook_url:
            self.logger.error("Missing required webhook_url")
            return False
            
        if not self.webhook_url.startswith('https://hooks.slack.com/'):
            self.logger.error("Invalid webhook URL format")
            return False
            
        return True

    def format_findings_blocks(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format findings as Slack blocks.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            List of Slack block objects
        """
        blocks = []
        
        if findings:
            blocks.append({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Security Findings"
                }
            })
            
            for finding in findings:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{finding.get('title', 'Untitled Finding')}*\n{finding.get('description', 'No description provided')}"
                    }
                })
                
                if 'severity' in finding:
                    blocks.append({
                        "type": "context",
                        "elements": [{
                            "type": "mrkdwn",
                            "text": f"Severity: *{finding['severity']}*"
                        }]
                    })
                    
                blocks.append({"type": "divider"})
                
        return blocks

    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send alert through Slack.
        
        Args:
            alert: Alert information dictionary
            
        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        try:
            severity_emojis = {
                'CRITICAL': ':red_circle:',
                'HIGH': ':orange_circle:',
                'MEDIUM': ':large_yellow_circle:',
                'LOW': ':large_blue_circle:',
                'INFO': ':white_circle:'
            }
            
            severity_emoji = severity_emojis.get(alert['severity'], ':warning:')
            
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{severity_emoji} {alert['title']}"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Severity:*\n{alert['severity']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Source:*\n{alert['source']}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": alert['message']
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"Alert Time: {alert['timestamp']}"
                        }
                    ]
                }
            ]
            
            # Add findings if present
            if alert['findings']:
                blocks.extend(self.format_findings_blocks(alert['findings']))
            
            payload = {
                "channel": self.channel,
                "username": self.username,
                "icon_emoji": self.icon_emoji,
                "blocks": blocks
            }
            
            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code != 200:
                self.logger.error(f"Failed to send Slack alert. Status: {response.status_code}, Response: {response.text}")
                return False
                
            self.logger.info("Alert sent successfully to Slack")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {str(e)}")
            return False 