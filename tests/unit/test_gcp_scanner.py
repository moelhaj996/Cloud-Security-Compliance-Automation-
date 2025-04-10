"""Unit tests for GCP Security Scanner."""

import unittest
from unittest.mock import Mock, patch
from datetime import datetime
from src.cloud_scanners.gcp.gcp_scanner import GCPSecurityScanner

class TestGCPSecurityScanner(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.project_id = "test-project-id"
        self.mock_credentials = Mock()
        self.scanner = GCPSecurityScanner(
            project_id=self.project_id,
            credentials=self.mock_credentials
        )

    def test_init(self):
        """Test scanner initialization."""
        self.assertEqual(self.scanner.project_id, self.project_id)
        self.assertEqual(self.scanner.credentials, self.mock_credentials)
        self.assertEqual(self.scanner.findings, [])

    def test_init_without_credentials(self):
        """Test scanner initialization without credentials."""
        scanner = GCPSecurityScanner(project_id=self.project_id)
        self.assertIsNone(scanner.credentials)

    def test_scan_all(self):
        """Test scan_all method returns correct structure."""
        result = self.scanner.scan_all()
        
        self.assertIn('timestamp', result)
        self.assertIn('project_id', result)
        self.assertIn('findings', result)
        self.assertIn('services', result)
        
        services = result['services']
        self.assertIn('security_center', services)
        self.assertIn('storage', services)
        self.assertIn('iam', services)
        self.assertIn('networking', services)
        self.assertIn('compute', services)
        self.assertIn('logging', services)
        self.assertIn('kms', services)

    @patch('google.cloud.securitycenter_v1.SecurityCenterClient')
    def test_scan_security_center(self, mock_security_client):
        """Test Security Center scanning functionality."""
        result = self.scanner.scan_security_center()
        
        self.assertIn('status', result)
        self.assertIn('findings', result)
        findings = result['findings']
        self.assertIn('findings', findings)
        self.assertIn('settings', findings)
        self.assertIn('assets', findings)

    @patch('google.cloud.storage.Client')
    def test_scan_storage(self, mock_storage_client):
        """Test Storage scanning functionality."""
        mock_bucket = Mock()
        mock_bucket.name = "testbucket"
        mock_bucket.location = "US"
        mock_bucket.versioning_enabled = True
        
        self.scanner.storage_client.list_buckets.return_value = [mock_bucket]
        
        result = self.scanner.scan_storage()
        
        self.assertIn('status', result)
        self.assertIn('findings', result)
        self.assertEqual(len(result['findings']), 1)
        
        finding = result['findings'][0]
        self.assertEqual(finding['name'], "testbucket")
        self.assertEqual(finding['location'], "US")
        self.assertTrue(finding['versioning'])

    def test_scan_iam(self):
        """Test IAM scanning functionality."""
        result = self.scanner.scan_iam()
        
        self.assertIn('status', result)
        self.assertIn('findings', result)
        findings = result['findings']
        self.assertIn('service_accounts', findings)
        self.assertIn('custom_roles', findings)
        self.assertIn('policy_bindings', findings)
        self.assertIn('key_rotation', findings)

    def test_scan_compute(self):
        """Test Compute Engine scanning functionality."""
        result = self.scanner.scan_compute()
        
        self.assertIn('status', result)
        self.assertIn('findings', result)
        findings = result['findings']
        self.assertIn('instances', findings)
        self.assertIn('disks', findings)
        self.assertIn('snapshots', findings)
        self.assertIn('os_login', findings)

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

    @patch('google.cloud.securitycenter_v1.SecurityCenterClient')
    def test_check_security_findings(self, mock_security_client):
        """Test security findings check functionality."""
        mock_finding = Mock()
        mock_finding.name = "test-finding"
        mock_finding.state = "ACTIVE"
        mock_finding.category = "VULNERABILITY"
        mock_finding.severity = "HIGH"
        mock_finding.event_time.isoformat.return_value = "2024-01-01T00:00:00Z"
        
        mock_security_client.list_findings.return_value = [mock_finding]
        result = self.scanner._check_security_findings()
        
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(len(result['findings']), 1)
        finding = result['findings'][0]
        self.assertEqual(finding['name'], "test-finding")
        self.assertEqual(finding['state'], "ACTIVE")
        self.assertEqual(finding['category'], "VULNERABILITY")
        self.assertEqual(finding['severity'], "HIGH")

if __name__ == '__main__':
    unittest.main() 