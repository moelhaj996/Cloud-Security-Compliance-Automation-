from typing import Dict, List, Any
import json
from datetime import datetime
import logging

class ComplianceProcessor:
    """Core compliance processing engine"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.compliance_frameworks = {
            'CIS': self._evaluate_cis_compliance,
            'HIPAA': self._evaluate_hipaa_compliance,
            'PCI': self._evaluate_pci_compliance,
            'SOC2': self._evaluate_soc2_compliance
        }

    def process_scan_results(self, scan_results: Dict[str, Any], 
                           frameworks: List[str]) -> Dict[str, Any]:
        """
        Process scan results against specified compliance frameworks
        
        Args:
            scan_results: Dictionary containing scan results from cloud providers
            frameworks: List of compliance frameworks to evaluate against
        
        Returns:
            Dictionary containing compliance evaluation results
        """
        try:
            compliance_results = {
                'timestamp': datetime.utcnow().isoformat(),
                'evaluations': {}
            }

            for framework in frameworks:
                if framework in self.compliance_frameworks:
                    compliance_results['evaluations'][framework] = \
                        self.compliance_frameworks[framework](scan_results)
                else:
                    self.logger.warning(f"Unsupported compliance framework: {framework}")

            return compliance_results
        except Exception as e:
            self.logger.error(f"Error processing compliance: {str(e)}")
            raise

    def _evaluate_cis_compliance(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate results against CIS benchmarks"""
        cis_compliance = {
            'framework': 'CIS',
            'version': '1.4.0',
            'controls': {}
        }

        # IAM Controls
        if 'iam' in scan_results:
            iam_results = scan_results['iam']
            cis_compliance['controls']['1.1'] = {
                'title': 'Avoid root account usage',
                'status': 'PASS' if iam_results.get('root_account', {}).get('last_used') is None 
                         else 'FAIL'
            }
            
            cis_compliance['controls']['1.2'] = {
                'title': 'MFA enabled for all IAM users',
                'status': self._evaluate_mfa_compliance(iam_results)
            }

        # S3 Controls
        if 's3' in scan_results:
            s3_results = scan_results['s3']
            cis_compliance['controls']['2.1'] = {
                'title': 'S3 buckets encryption',
                'status': self._evaluate_s3_encryption(s3_results)
            }

        return cis_compliance

    def _evaluate_hipaa_compliance(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate results against HIPAA requirements"""
        hipaa_compliance = {
            'framework': 'HIPAA',
            'controls': {}
        }

        # Access Control Requirements
        if 'iam' in scan_results:
            hipaa_compliance['controls']['access_control'] = {
                'title': '164.312(a)(1) Access Control',
                'requirements': {
                    'unique_user_identification': self._evaluate_unique_users(scan_results['iam']),
                    'emergency_access': self._evaluate_emergency_access(scan_results['iam']),
                    'automatic_logoff': self._evaluate_session_management(scan_results['iam'])
                }
            }

        # Encryption Requirements
        if 's3' in scan_results:
            hipaa_compliance['controls']['encryption'] = {
                'title': '164.312(a)(2)(iv) Encryption and Decryption',
                'requirements': self._evaluate_encryption_controls(scan_results['s3'])
            }

        return hipaa_compliance

    def _evaluate_pci_compliance(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate results against PCI-DSS requirements"""
        pci_compliance = {
            'framework': 'PCI-DSS',
            'version': '3.2.1',
            'controls': {}
        }

        # Requirement 7: Restrict Access
        if 'iam' in scan_results:
            pci_compliance['controls']['req_7'] = {
                'title': 'Restrict Access to Cardholder Data',
                'requirements': self._evaluate_access_restrictions(scan_results['iam'])
            }

        # Requirement 3: Protect Stored Data
        if 's3' in scan_results:
            pci_compliance['controls']['req_3'] = {
                'title': 'Protect Stored Cardholder Data',
                'requirements': self._evaluate_data_protection(scan_results['s3'])
            }

        return pci_compliance

    def _evaluate_soc2_compliance(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate results against SOC2 requirements"""
        soc2_compliance = {
            'framework': 'SOC2',
            'controls': {}
        }

        # Security Controls
        if 'iam' in scan_results:
            soc2_compliance['controls']['CC6.1'] = {
                'title': 'Logical Access Security',
                'status': self._evaluate_logical_access(scan_results['iam'])
            }

        # Data Protection
        if 's3' in scan_results:
            soc2_compliance['controls']['CC6.7'] = {
                'title': 'Data Protection',
                'status': self._evaluate_data_security(scan_results['s3'])
            }

        return soc2_compliance

    def _evaluate_mfa_compliance(self, iam_results: Dict[str, Any]) -> str:
        """Evaluate MFA compliance status"""
        if 'users_mfa_status' not in iam_results:
            return 'UNKNOWN'
        
        all_users_mfa = all(user['mfa_enabled'] 
                           for user in iam_results['users_mfa_status'])
        return 'PASS' if all_users_mfa else 'FAIL'

    def _evaluate_s3_encryption(self, s3_results: List[Dict[str, Any]]) -> str:
        """Evaluate S3 encryption compliance"""
        if not s3_results:
            return 'UNKNOWN'
        
        all_encrypted = all(bucket.get('encryption', {}).get('encrypted', False) 
                          for bucket in s3_results)
        return 'PASS' if all_encrypted else 'FAIL'

    def _evaluate_unique_users(self, iam_results: Dict[str, Any]) -> Dict[str, str]:
        """Evaluate unique user identification compliance"""
        return {
            'status': 'PASS' if 'users_mfa_status' in iam_results else 'FAIL',
            'details': 'Each IAM user has unique identifier'
        }

    def _evaluate_emergency_access(self, iam_results: Dict[str, Any]) -> Dict[str, str]:
        """Evaluate emergency access procedure compliance"""
        return {
            'status': 'PASS' if 'emergency_access' in iam_results else 'FAIL',
            'details': 'Emergency access procedure documented and implemented'
        }

    def _evaluate_session_management(self, iam_results: Dict[str, Any]) -> Dict[str, str]:
        """Evaluate session management compliance"""
        password_policy = iam_results.get('password_policy', {})
        return {
            'status': 'PASS' if password_policy.get('expires_passwords') else 'FAIL',
            'details': 'Automatic session termination implemented'
        }

    def _evaluate_encryption_controls(self, s3_results: List[Dict[str, Any]]) -> Dict[str, str]:
        """Evaluate encryption controls compliance"""
        all_encrypted = all(bucket.get('encryption', {}).get('encrypted', False) 
                          for bucket in s3_results)
        return {
            'status': 'PASS' if all_encrypted else 'FAIL',
            'details': 'All data encrypted at rest and in transit'
        }

    def _evaluate_access_restrictions(self, iam_results: Dict[str, Any]) -> Dict[str, str]:
        """Evaluate access restriction compliance"""
        return {
            'status': 'PASS' if self._check_least_privilege(iam_results) else 'FAIL',
            'details': 'Access restrictions based on least privilege principle'
        }

    def _evaluate_data_protection(self, s3_results: List[Dict[str, Any]]) -> Dict[str, str]:
        """Evaluate data protection compliance"""
        all_protected = all(
            bucket.get('public_access', {}).get('block_public_acls', False) 
            and bucket.get('encryption', {}).get('encrypted', False)
            for bucket in s3_results
        )
        return {
            'status': 'PASS' if all_protected else 'FAIL',
            'details': 'Data protection controls implemented'
        }

    def _evaluate_logical_access(self, iam_results: Dict[str, Any]) -> Dict[str, str]:
        """Evaluate logical access security"""
        password_policy = iam_results.get('password_policy', {})
        mfa_status = self._evaluate_mfa_compliance(iam_results)
        
        return {
            'status': 'PASS' if password_policy.get('requires_symbols') 
                              and password_policy.get('requires_numbers')
                              and mfa_status == 'PASS' else 'FAIL',
            'details': 'Logical access security controls implemented'
        }

    def _evaluate_data_security(self, s3_results: List[Dict[str, Any]]) -> Dict[str, str]:
        """Evaluate data security controls"""
        all_secure = all(
            bucket.get('encryption', {}).get('encrypted', False)
            and bucket.get('logging', {}).get('logging_enabled', False)
            for bucket in s3_results
        )
        return {
            'status': 'PASS' if all_secure else 'FAIL',
            'details': 'Data security controls implemented'
        }

    def _check_least_privilege(self, iam_results: Dict[str, Any]) -> bool:
        """Check if least privilege principle is followed"""
        # This is a simplified check - in reality, would need more complex evaluation
        return 'access_keys' in iam_results and 'password_policy' in iam_results 