"""Unit tests for AWS Security Scanner."""

import unittest
from unittest.mock import Mock, patch
from datetime import datetime
from src.cloud_scanners.aws.aws_scanner import AWSSecurityScanner

class TestAWSSecurityScanner(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.mock_session = Mock()
        self.scanner = AWSSecurityScanner(session=self.mock_session)

    def test_init(self):
        """Test scanner initialization."""
        self.assertEqual(self.scanner.findings, [])
        self.assertEqual(self.scanner.session, self.mock_session)

    @patch('boto3.Session')
    def test_init_without_session(self, mock_boto3_session):
        """Test scanner initialization without session."""
        scanner = AWSSecurityScanner()
        mock_boto3_session.assert_called_once()

    def test_scan_all(self):
        """Test scan_all method returns correct structure."""
        result = self.scanner.scan_all()
        
        self.assertIn('timestamp', result)
        self.assertIn('region', result)
        self.assertIn('findings', result)
        self.assertIn('services', result)
        
        services = result['services']
        self.assertIn('iam', services)
        self.assertIn('s3', services)
        self.assertIn('ec2', services)
        self.assertIn('rds', services)
        self.assertIn('cloudtrail', services)
        self.assertIn('kms', services)
        self.assertIn('config', services)
        self.assertIn('guardduty', services)

    def test_scan_iam(self):
        """Test IAM scanning functionality."""
        mock_iam = Mock()
        self.mock_session.client.return_value = mock_iam
        
        result = self.scanner.scan_iam()
        
        self.assertIn('status', result)
        self.assertIn('findings', result)
        self.mock_session.client.assert_called_with('iam')

    def test_scan_s3(self):
        """Test S3 scanning functionality."""
        mock_s3 = Mock()
        mock_s3.list_buckets.return_value = {'Buckets': []}
        self.mock_session.client.return_value = mock_s3
        
        result = self.scanner.scan_s3()
        
        self.assertIn('status', result)
        self.assertIn('findings', result)
        self.mock_session.client.assert_called_with('s3')

    def test_add_finding(self):
        """Test adding security findings."""
        self.scanner.add_finding(
            service='test',
            severity='HIGH',
            title='Test Finding',
            description='Test Description'
        )
        
        self.assertEqual(len(self.scanner.findings), 1)
        finding = self.scanner.findings[0]
        
        self.assertEqual(finding['service'], 'test')
        self.assertEqual(finding['severity'], 'HIGH')
        self.assertEqual(finding['title'], 'Test Finding')
        self.assertEqual(finding['description'], 'Test Description')
        self.assertIn('timestamp', finding)

if __name__ == '__main__':
    unittest.main() 