"""Alert Manager for Cloud Security Compliance Automation."""

from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod
from datetime import datetime
import logging
from enum import Enum

class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class NotificationChannel(ABC):
    """Abstract base class for notification channels."""
    
    @abstractmethod
    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send an alert through the notification channel.
        
        Args:
            alert: Dictionary containing alert information
            
        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        pass

    @abstractmethod
    def validate_config(self) -> bool:
        """Validate the channel configuration.
        
        Returns:
            bool: True if configuration is valid, False otherwise
        """
        pass

class AlertManager:
    """Manages security and compliance alerts across different notification channels."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the Alert Manager.
        
        Args:
            config: Configuration dictionary containing notification channel settings
        """
        self.config = config
        self.channels: Dict[str, NotificationChannel] = {}
        self.logger = logging.getLogger(__name__)
        self._initialize_channels()

    def _initialize_channels(self) -> None:
        """Initialize configured notification channels."""
        if 'channels' not in self.config:
            self.logger.warning("No notification channels configured")
            return

        for channel_config in self.config['channels']:
            try:
                channel_type = channel_config['type']
                if channel_type == 'email':
                    from .channels.email import EmailChannel
                    channel = EmailChannel(channel_config)
                elif channel_type == 'slack':
                    from .channels.slack import SlackChannel
                    channel = SlackChannel(channel_config)
                # Add more channel types here
                
                if channel.validate_config():
                    self.channels[channel_type] = channel
                else:
                    self.logger.error(f"Invalid configuration for channel: {channel_type}")
            except Exception as e:
                self.logger.error(f"Failed to initialize channel {channel_type}: {str(e)}")

    def send_alert(self, 
                  title: str,
                  message: str,
                  severity: AlertSeverity,
                  source: str,
                  findings: Optional[List[Dict[str, Any]]] = None,
                  channel_override: Optional[List[str]] = None) -> Dict[str, Any]:
        """Send an alert through configured notification channels.
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity level
            source: Source of the alert (e.g., 'aws_scanner', 'azure_scanner')
            findings: Optional list of security findings
            channel_override: Optional list of specific channels to use
            
        Returns:
            Dict containing the alert status for each channel
        """
        alert = {
            'title': title,
            'message': message,
            'severity': severity.value,
            'source': source,
            'timestamp': datetime.utcnow().isoformat(),
            'findings': findings or []
        }

        results = {}
        channels_to_use = channel_override or self.channels.keys()

        for channel_name in channels_to_use:
            if channel_name not in self.channels:
                results[channel_name] = {
                    'status': 'error',
                    'message': f'Channel {channel_name} not configured'
                }
                continue

            try:
                channel = self.channels[channel_name]
                success = channel.send_alert(alert)
                results[channel_name] = {
                    'status': 'success' if success else 'error',
                    'message': 'Alert sent successfully' if success else 'Failed to send alert'
                }
            except Exception as e:
                results[channel_name] = {
                    'status': 'error',
                    'message': str(e)
                }
                self.logger.error(f"Error sending alert through {channel_name}: {str(e)}")

        return results

    def get_active_channels(self) -> List[str]:
        """Get list of active notification channels.
        
        Returns:
            List of active channel names
        """
        return list(self.channels.keys())

    def validate_channels(self) -> Dict[str, bool]:
        """Validate all configured channels.
        
        Returns:
            Dictionary mapping channel names to their validation status
        """
        return {
            name: channel.validate_config()
            for name, channel in self.channels.items()
        } 