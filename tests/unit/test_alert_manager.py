"""Unit tests for Alert Manager and notification channels."""

import unittest
from unittest.mock import Mock, patch
from datetime import datetime
from src.alert_system.alert_manager import AlertManager, AlertSeverity, NotificationChannel
from src.alert_system.channels.email import EmailChannel
from src.alert_system.channels.slack import SlackChannel

class MockChannel(NotificationChannel):
    """Mock notification channel for testing."""
    
    def __init__(self, should_succeed=True):
        self.should_succeed = should_succeed
        self.last_alert = None
        
    def send_alert(self, alert):
        self.last_alert = alert
        return self.should_succeed
        
    def validate_config(self):
        return True

class TestAlertManager(unittest.TestCase):
    """Test cases for Alert Manager."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'channels': [
                {
                    'type': 'mock',
                    'should_succeed': True
                }
            ]
        }
        self.alert_manager = AlertManager(self.config)
        self.mock_channel = MockChannel()
        self.alert_manager.channels['mock'] = self.mock_channel

    def test_init(self):
        """Test alert manager initialization."""
        self.assertEqual(self.alert_manager.config, self.config)
        self.assertIsInstance(self.alert_manager.channels, dict)

    def test_send_alert(self):
        """Test sending alerts through configured channels."""
        result = self.alert_manager.send_alert(
            title="Test Alert",
            message="Test Message",
            severity=AlertSeverity.HIGH,
            source="test_source"
        )
        
        self.assertIn('mock', result)
        self.assertEqual(result['mock']['status'], 'success')
        
        last_alert = self.mock_channel.last_alert
        self.assertEqual(last_alert['title'], "Test Alert")
        self.assertEqual(last_alert['message'], "Test Message")
        self.assertEqual(last_alert['severity'], "HIGH")
        self.assertEqual(last_alert['source'], "test_source")

    def test_send_alert_with_findings(self):
        """Test sending alerts with security findings."""
        findings = [{
            'title': 'Test Finding',
            'description': 'Test Description',
            'severity': 'HIGH'
        }]
        
        result = self.alert_manager.send_alert(
            title="Test Alert",
            message="Test Message",
            severity=AlertSeverity.HIGH,
            source="test_source",
            findings=findings
        )
        
        self.assertIn('mock', result)
        self.assertEqual(result['mock']['status'], 'success')
        
        last_alert = self.mock_channel.last_alert
        self.assertEqual(last_alert['findings'], findings)

    def test_send_alert_channel_failure(self):
        """Test handling of channel failures."""
        failing_channel = MockChannel(should_succeed=False)
        self.alert_manager.channels['failing'] = failing_channel
        
        result = self.alert_manager.send_alert(
            title="Test Alert",
            message="Test Message",
            severity=AlertSeverity.HIGH,
            source="test_source"
        )
        
        self.assertEqual(result['failing']['status'], 'error')

    def test_channel_override(self):
        """Test channel override functionality."""
        self.alert_manager.channels['extra'] = MockChannel()
        
        result = self.alert_manager.send_alert(
            title="Test Alert",
            message="Test Message",
            severity=AlertSeverity.HIGH,
            source="test_source",
            channel_override=['mock']
        )
        
        self.assertIn('mock', result)
        self.assertNotIn('extra', result)

class TestEmailChannel(unittest.TestCase):
    """Test cases for Email Channel."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'smtp_host': 'smtp.test.com',
            'smtp_port': 587,
            'smtp_username': 'test@test.com',
            'smtp_password': 'password',
            'from_address': 'alerts@test.com',
            'recipients': ['recipient@test.com']
        }
        self.channel = EmailChannel(self.config)

    def test_validate_config(self):
        """Test email channel configuration validation."""
        self.assertTrue(self.channel.validate_config())
        
        # Test invalid config
        invalid_channel = EmailChannel({})
        self.assertFalse(invalid_channel.validate_config())

    @patch('smtplib.SMTP')
    def test_send_alert(self, mock_smtp):
        """Test sending email alerts."""
        mock_smtp_instance = Mock()
        mock_smtp.return_value.__enter__.return_value = mock_smtp_instance
        
        alert = {
            'title': 'Test Alert',
            'message': 'Test Message',
            'severity': 'HIGH',
            'source': 'test_source',
            'timestamp': datetime.utcnow().isoformat(),
            'findings': []
        }
        
        result = self.channel.send_alert(alert)
        
        self.assertTrue(result)
        mock_smtp_instance.starttls.assert_called_once()
        mock_smtp_instance.login.assert_called_once_with(
            self.config['smtp_username'],
            self.config['smtp_password']
        )
        mock_smtp_instance.send_message.assert_called_once()

class TestSlackChannel(unittest.TestCase):
    """Test cases for Slack Channel."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'webhook_url': 'https://hooks.slack.com/services/xxx/yyy/zzz',
            'channel': '#security-alerts'
        }
        self.channel = SlackChannel(self.config)

    def test_validate_config(self):
        """Test Slack channel configuration validation."""
        self.assertTrue(self.channel.validate_config())
        
        # Test invalid config
        invalid_channel = SlackChannel({})
        self.assertFalse(invalid_channel.validate_config())
        
        # Test invalid webhook URL
        invalid_channel = SlackChannel({'webhook_url': 'https://invalid.url'})
        self.assertFalse(invalid_channel.validate_config())

    @patch('requests.post')
    def test_send_alert(self, mock_post):
        """Test sending Slack alerts."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        alert = {
            'title': 'Test Alert',
            'message': 'Test Message',
            'severity': 'HIGH',
            'source': 'test_source',
            'timestamp': datetime.utcnow().isoformat(),
            'findings': []
        }
        
        result = self.channel.send_alert(alert)
        
        self.assertTrue(result)
        mock_post.assert_called_once()
        
        # Verify payload structure
        call_args = mock_post.call_args
        self.assertEqual(call_args[1]['headers']['Content-Type'], 'application/json')
        
        payload = json.loads(call_args[1]['data'])
        self.assertEqual(payload['channel'], self.config['channel'])
        self.assertIn('blocks', payload)

if __name__ == '__main__':
    unittest.main() 