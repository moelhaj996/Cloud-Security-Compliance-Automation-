"""
GCP Security Scanner for Cloud Security Compliance Automation.
Performs comprehensive security checks across GCP services.
"""

from typing import Dict, List, Any
from datetime import datetime
from google.cloud import storage
from google.cloud import monitoring_v3
from google.cloud import asset_v1
from google.cloud import securitycenter_v1
from google.cloud import iam_v1
from google.cloud.audit_logs_v1 import AuditLogsClient

class GCPSecurityScanner:
    def __init__(self, project_id: str, credentials=None):
        """
        Initialize GCP Security Scanner.
        
        Args:
            project_id: GCP project ID
            credentials: Optional GCP credentials object
        """
        self.project_id = project_id
        self.credentials = credentials
        self.findings = []
        
        # Initialize clients
        self.storage_client = storage.Client(project=project_id, credentials=credentials)
        self.monitoring_client = monitoring_v3.MetricServiceClient(credentials=credentials)
        self.asset_client = asset_v1.AssetServiceClient(credentials=credentials)
        self.security_client = securitycenter_v1.SecurityCenterClient(credentials=credentials)
        self.iam_client = iam_v1.IAMClient(credentials=credentials)
        self.audit_client = AuditLogsClient(credentials=credentials)

    def scan_all(self) -> Dict[str, Any]:
        """
        Perform all security scans.
        
        Returns:
            Dict containing all scan results
        """
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'project_id': self.project_id,
            'findings': self.findings,
            'services': {
                'security_center': self.scan_security_center(),
                'storage': self.scan_storage(),
                'iam': self.scan_iam(),
                'networking': self.scan_networking(),
                'compute': self.scan_compute(),
                'logging': self.scan_logging(),
                'kms': self.scan_kms()
            }
        }

    def scan_security_center(self) -> Dict[str, Any]:
        """Scan Security Command Center findings and settings."""
        try:
            findings = {
                'findings': self._check_security_findings(),
                'settings': self._check_security_settings(),
                'assets': self._check_security_assets()
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_storage(self) -> Dict[str, Any]:
        """Scan Cloud Storage bucket configurations."""
        try:
            findings = []
            for bucket in self.storage_client.list_buckets():
                findings.append({
                    'name': bucket.name,
                    'location': bucket.location,
                    'iam_config': self._check_bucket_iam(bucket),
                    'encryption': self._check_bucket_encryption(bucket),
                    'logging': self._check_bucket_logging(bucket),
                    'versioning': bucket.versioning_enabled,
                    'public_access': self._check_bucket_public_access(bucket)
                })
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_iam(self) -> Dict[str, Any]:
        """Scan IAM policies and service accounts."""
        try:
            findings = {
                'service_accounts': self._check_service_accounts(),
                'custom_roles': self._check_custom_roles(),
                'policy_bindings': self._check_policy_bindings(),
                'key_rotation': self._check_key_rotation()
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_networking(self) -> Dict[str, Any]:
        """Scan VPC and networking configurations."""
        try:
            findings = {
                'firewalls': self._check_firewall_rules(),
                'vpc_flow_logs': self._check_vpc_flow_logs(),
                'ssl_policies': self._check_ssl_policies(),
                'cloud_nat': self._check_cloud_nat()
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_compute(self) -> Dict[str, Any]:
        """Scan Compute Engine configurations."""
        try:
            findings = {
                'instances': self._check_compute_instances(),
                'disks': self._check_compute_disks(),
                'snapshots': self._check_compute_snapshots(),
                'os_login': self._check_os_login()
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_logging(self) -> Dict[str, Any]:
        """Scan Cloud Logging and monitoring configurations."""
        try:
            findings = {
                'audit_logs': self._check_audit_logging(),
                'log_sinks': self._check_log_sinks(),
                'metrics': self._check_logging_metrics(),
                'alerts': self._check_monitoring_alerts()
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_kms(self) -> Dict[str, Any]:
        """Scan Cloud KMS configurations."""
        try:
            findings = {
                'keys': self._check_kms_keys(),
                'key_rotation': self._check_key_rotation_settings(),
                'key_protection': self._check_key_protection_level()
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    # Helper methods for Security Center checks
    def _check_security_findings(self) -> Dict[str, Any]:
        """Check Security Command Center findings."""
        try:
            parent = f"projects/{self.project_id}"
            findings = []
            request = securitycenter_v1.ListFindingsRequest(parent=parent)
            
            for finding in self.security_client.list_findings(request=request):
                findings.append({
                    'name': finding.name,
                    'state': finding.state,
                    'category': finding.category,
                    'severity': finding.severity,
                    'event_time': finding.event_time.isoformat() if finding.event_time else None
                })
            return {'status': 'ok', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    # Helper methods for Storage checks
    def _check_bucket_iam(self, bucket) -> Dict[str, Any]:
        """Check bucket IAM permissions."""
        try:
            policy = bucket.get_iam_policy()
            return {
                'bindings': [
                    {'role': binding['role'], 'members': binding['members']}
                    for binding in policy
                ]
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _check_bucket_encryption(self, bucket) -> Dict[str, Any]:
        """Check bucket encryption settings."""
        try:
            encryption = bucket.encryption_configuration
            return {
                'enabled': encryption is not None,
                'type': encryption.kms_key_name if encryption else None
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