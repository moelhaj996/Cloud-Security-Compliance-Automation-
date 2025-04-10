"""
Azure Security Scanner for Cloud Security Compliance Automation.
Performs comprehensive security checks across Azure services.
"""

from typing import Dict, List, Any
from datetime import datetime
from azure.identity import DefaultAzureCredential
from azure.mgmt.security import SecurityCenter
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient

class AzureSecurityScanner:
    def __init__(self, subscription_id: str, credential: DefaultAzureCredential = None):
        """
        Initialize Azure Security Scanner.
        
        Args:
            subscription_id: Azure subscription ID
            credential: Optional Azure credential object
        """
        self.subscription_id = subscription_id
        self.credential = credential or DefaultAzureCredential()
        self.findings = []
        
        # Initialize clients
        self.security_client = SecurityCenter(self.credential, self.subscription_id)
        self.monitor_client = MonitorManagementClient(self.credential, self.subscription_id)
        self.storage_client = StorageManagementClient(self.credential, self.subscription_id)
        self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
        self.keyvault_client = KeyVaultManagementClient(self.credential, self.subscription_id)

    def scan_all(self) -> Dict[str, Any]:
        """
        Perform all security scans.
        
        Returns:
            Dict containing all scan results
        """
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'subscription_id': self.subscription_id,
            'findings': self.findings,
            'services': {
                'security_center': self.scan_security_center(),
                'storage': self.scan_storage(),
                'keyvault': self.scan_keyvault(),
                'network': self.scan_network(),
                'identity': self.scan_identity(),
                'monitoring': self.scan_monitoring()
            }
        }

    def scan_security_center(self) -> Dict[str, Any]:
        """Scan Azure Security Center settings and recommendations."""
        try:
            findings = {
                'secure_score': self._check_secure_score(),
                'security_contacts': self._check_security_contacts(),
                'pricing_tier': self._check_pricing_tier(),
                'assessments': self._check_security_assessments()
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_storage(self) -> Dict[str, Any]:
        """Scan Azure Storage Account configurations."""
        try:
            findings = []
            for account in self.storage_client.storage_accounts.list():
                findings.append({
                    'name': account.name,
                    'https_only': account.enable_https_traffic_only,
                    'encryption': self._check_storage_encryption(account),
                    'network_rules': self._check_storage_network_rules(account),
                    'blob_service_properties': self._check_blob_service_properties(account)
                })
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_keyvault(self) -> Dict[str, Any]:
        """Scan Azure Key Vault configurations."""
        try:
            findings = []
            for vault in self.keyvault_client.vaults.list():
                findings.append({
                    'name': vault.name,
                    'sku': vault.properties.sku.name,
                    'soft_delete': vault.properties.enable_soft_delete,
                    'purge_protection': vault.properties.enable_purge_protection,
                    'network_acls': self._check_vault_network_rules(vault),
                    'access_policies': self._check_vault_access_policies(vault)
                })
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_network(self) -> Dict[str, Any]:
        """Scan Azure Network security configurations."""
        try:
            findings = {
                'network_watcher': self._check_network_watcher(),
                'ddos_protection': self._check_ddos_protection(),
                'flow_logs': self._check_flow_logs()
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_identity(self) -> Dict[str, Any]:
        """Scan Azure AD and managed identities."""
        try:
            findings = {
                'managed_identities': self._check_managed_identities(),
                'rbac_assignments': self._check_rbac_assignments()
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_monitoring(self) -> Dict[str, Any]:
        """Scan Azure monitoring and diagnostics settings."""
        try:
            findings = {
                'activity_log': self._check_activity_log(),
                'diagnostic_settings': self._check_diagnostic_settings(),
                'log_profiles': self._check_log_profiles()
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    # Helper methods for Security Center checks
    def _check_secure_score(self) -> Dict[str, Any]:
        """Check Security Center secure score."""
        try:
            scores = list(self.security_client.secure_scores.list())
            return {'status': 'ok', 'scores': [
                {'name': score.name, 'current_score': score.current.score}
                for score in scores
            ]}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _check_security_contacts(self) -> Dict[str, Any]:
        """Check Security Center contact information."""
        try:
            contacts = list(self.security_client.security_contacts.list())
            return {'status': 'ok', 'contacts': [
                {'email': contact.email, 'phone': contact.phone}
                for contact in contacts
            ]}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    # Helper methods for Storage checks
    def _check_storage_encryption(self, account) -> Dict[str, Any]:
        """Check storage account encryption settings."""
        try:
            return {
                'status': 'enabled' if account.encryption.services.blob.enabled else 'disabled',
                'key_type': account.encryption.key_source
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _check_storage_network_rules(self, account) -> Dict[str, Any]:
        """Check storage account network rules."""
        try:
            rules = self.storage_client.storage_accounts.get_network_rule_set(
                account.resource_group_name,
                account.name
            )
            return {
                'default_action': rules.default_action,
                'ip_rules': [rule.ip_address_or_range for rule in rules.ip_rules],
                'virtual_network_rules': [rule.virtual_network_resource_id 
                                       for rule in rules.virtual_network_rules]
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def add_finding(self, service: str, severity: str, title: str, description: str):
        """Add a security finding to the findings list."""
        self.findings.append({
            'timestamp': datetime.utcnow().isoformat(),
            'service': service,
            'severity': severity,
            'title': title,
            'description': description
        }) 