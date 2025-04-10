"""Unit tests for Azure Security Scanner."""

import unittest
from unittest.mock import Mock, patch
from datetime import datetime
from src.cloud_scanners.azure.azure_scanner import AzureSecurityScanner

class TestAzureSecurityScanner(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.subscription_id = "test-subscription-id"
        self.mock_credential = Mock()
        self.scanner = AzureSecurityScanner(
            subscription_id=self.subscription_id,
            credential=self.mock_credential
        )

    def test_init(self):
        """Test scanner initialization."""
        self.assertEqual(self.scanner.subscription_id, self.subscription_id)
        self.assertEqual(self.scanner.credential, self.mock_credential)
        self.assertEqual(self.scanner.findings, [])

    @patch('azure.identity.DefaultAzureCredential')
    def test_init_without_credential(self, mock_default_credential):
        """Test scanner initialization without credential."""
        scanner = AzureSecurityScanner(subscription_id=self.subscription_id)
        mock_default_credential.assert_called_once()

    def test_scan_all(self):
        """Test scan_all method returns correct structure."""
        result = self.scanner.scan_all()
        
        self.assertIn('timestamp', result)
        self.assertIn('subscription_id', result)
        self.assertIn('findings', result)
        self.assertIn('services', result)
        
        services = result['services']
        self.assertIn('security_center', services)
        self.assertIn('storage', services)
        self.assertIn('keyvault', services)
        self.assertIn('network', services)
        self.assertIn('identity', services)
        self.assertIn('monitoring', services)

    def test_scan_security_center(self):
        """Test Security Center scanning functionality."""
        result = self.scanner.scan_security_center()
        
        self.assertIn('status', result)
        self.assertIn('findings', result)
        findings = result['findings']
        self.assertIn('secure_score', findings)
        self.assertIn('security_contacts', findings)
        self.assertIn('pricing_tier', findings)
        self.assertIn('assessments', findings)

    def test_scan_storage(self):
        """Test Storage Account scanning functionality."""
        mock_storage_account = Mock()
        mock_storage_account.name = "teststorage"
        mock_storage_account.enable_https_traffic_only = True
        
        self.scanner.storage_client.storage_accounts.list.return_value = [mock_storage_account]
        
        result = self.scanner.scan_storage()
        
        self.assertIn('status', result)
        self.assertIn('findings', result)
        self.assertEqual(len(result['findings']), 1)
        
        finding = result['findings'][0]
        self.assertEqual(finding['name'], "teststorage")
        self.assertTrue(finding['https_only'])

    def test_scan_keyvault(self):
        """Test Key Vault scanning functionality."""
        mock_vault = Mock()
        mock_vault.name = "testvault"
        mock_vault.properties.sku.name = "standard"
        mock_vault.properties.enable_soft_delete = True
        
        self.scanner.keyvault_client.vaults.list.return_value = [mock_vault]
        
        result = self.scanner.scan_keyvault()
        
        self.assertIn('status', result)
        self.assertIn('findings', result)
        self.assertEqual(len(result['findings']), 1)
        
        finding = result['findings'][0]
        self.assertEqual(finding['name'], "testvault")
        self.assertEqual(finding['sku'], "standard")
        self.assertTrue(finding['soft_delete'])

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

    @patch('azure.mgmt.security.SecurityCenter')
    def test_check_secure_score(self, mock_security_center):
        """Test secure score checking functionality."""
        mock_score = Mock()
        mock_score.name = "global"
        mock_score.current.score = 85
        
        mock_security_center.secure_scores.list.return_value = [mock_score]
        result = self.scanner._check_secure_score()
        
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(len(result['scores']), 1)
        self.assertEqual(result['scores'][0]['name'], "global")
        self.assertEqual(result['scores'][0]['current_score'], 85)

if __name__ == '__main__':
    unittest.main() 