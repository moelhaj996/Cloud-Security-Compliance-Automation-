"""
AWS Security Scanner for Cloud Security Compliance Automation.
Performs comprehensive security checks across AWS services.
"""

import boto3
from typing import Dict, List, Any
from datetime import datetime
from botocore.exceptions import ClientError

class AWSSecurityScanner:
    def __init__(self, session: boto3.Session = None):
        """
        Initialize AWS Security Scanner.
        
        Args:
            session: Optional boto3 session. If not provided, default credentials will be used.
        """
        self.session = session or boto3.Session()
        self.findings = []
        self.region = self.session.region_name or 'us-east-1'

    def scan_all(self) -> Dict[str, Any]:
        """
        Perform all security scans.
        
        Returns:
            Dict containing all scan results
        """
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'region': self.region,
            'findings': self.findings,
            'services': {
                'iam': self.scan_iam(),
                's3': self.scan_s3(),
                'ec2': self.scan_ec2(),
                'rds': self.scan_rds(),
                'cloudtrail': self.scan_cloudtrail(),
                'kms': self.scan_kms(),
                'config': self.scan_config(),
                'guardduty': self.scan_guardduty()
            }
        }

    def scan_iam(self) -> Dict[str, Any]:
        """Scan IAM configurations and policies."""
        try:
            iam = self.session.client('iam')
            findings = {
                'password_policy': self._check_password_policy(iam),
                'root_account': self._check_root_account(iam),
                'access_keys': self._check_access_keys(iam),
                'mfa': self._check_mfa_usage(iam)
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_s3(self) -> Dict[str, Any]:
        """Scan S3 buckets for security configurations."""
        try:
            s3 = self.session.client('s3')
            buckets = s3.list_buckets()['Buckets']
            findings = []

            for bucket in buckets:
                bucket_name = bucket['Name']
                findings.append({
                    'bucket': bucket_name,
                    'encryption': self._check_bucket_encryption(s3, bucket_name),
                    'public_access': self._check_bucket_public_access(s3, bucket_name),
                    'logging': self._check_bucket_logging(s3, bucket_name),
                    'versioning': self._check_bucket_versioning(s3, bucket_name)
                })

            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_ec2(self) -> Dict[str, Any]:
        """Scan EC2 instances and security groups."""
        try:
            ec2 = self.session.client('ec2')
            findings = {
                'instances': self._check_ec2_instances(ec2),
                'security_groups': self._check_security_groups(ec2),
                'ebs_encryption': self._check_ebs_encryption(ec2)
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_rds(self) -> Dict[str, Any]:
        """Scan RDS instances for security configurations."""
        try:
            rds = self.session.client('rds')
            findings = {
                'instances': self._check_rds_instances(rds),
                'encryption': self._check_rds_encryption(rds),
                'public_access': self._check_rds_public_access(rds)
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_cloudtrail(self) -> Dict[str, Any]:
        """Scan CloudTrail configuration."""
        try:
            cloudtrail = self.session.client('cloudtrail')
            findings = {
                'trails': self._check_trails(cloudtrail),
                'logging': self._check_trail_logging(cloudtrail),
                'encryption': self._check_trail_encryption(cloudtrail)
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_kms(self) -> Dict[str, Any]:
        """Scan KMS keys and their rotation policies."""
        try:
            kms = self.session.client('kms')
            findings = {
                'keys': self._check_kms_keys(kms),
                'rotation': self._check_key_rotation(kms)
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_config(self) -> Dict[str, Any]:
        """Scan AWS Config service status and rules."""
        try:
            config = self.session.client('config')
            findings = {
                'recorders': self._check_config_recorders(config),
                'rules': self._check_config_rules(config)
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def scan_guardduty(self) -> Dict[str, Any]:
        """Scan GuardDuty findings and detectors."""
        try:
            guardduty = self.session.client('guardduty')
            findings = {
                'detectors': self._check_guardduty_detectors(guardduty),
                'findings': self._check_guardduty_findings(guardduty)
            }
            return {'status': 'completed', 'findings': findings}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    # Helper methods for IAM checks
    def _check_password_policy(self, iam) -> Dict[str, Any]:
        try:
            policy = iam.get_account_password_policy()['PasswordPolicy']
            return {'status': 'ok', 'policy': policy}
        except ClientError:
            return {'status': 'error', 'message': 'No password policy set'}

    def _check_root_account(self, iam) -> Dict[str, Any]:
        try:
            summary = iam.get_account_summary()['SummaryMap']
            return {
                'access_keys': summary.get('AccountAccessKeysPresent', 0),
                'mfa': summary.get('AccountMFAEnabled', 0)
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    # Helper methods for S3 checks
    def _check_bucket_encryption(self, s3, bucket_name: str) -> Dict[str, Any]:
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            return {'status': 'enabled', 'config': encryption['ServerSideEncryptionConfiguration']}
        except ClientError:
            return {'status': 'disabled'}

    def _check_bucket_public_access(self, s3, bucket_name: str) -> Dict[str, Any]:
        try:
            public_access = s3.get_public_access_block(Bucket=bucket_name)
            return {'status': 'configured', 'config': public_access['PublicAccessBlockConfiguration']}
        except ClientError:
            return {'status': 'not_configured'}

    # Add implementation for other helper methods as needed

    def add_finding(self, service: str, severity: str, title: str, description: str):
        """Add a security finding to the findings list."""
        self.findings.append({
            'timestamp': datetime.utcnow().isoformat(),
            'service': service,
            'severity': severity,
            'title': title,
            'description': description
        }) 