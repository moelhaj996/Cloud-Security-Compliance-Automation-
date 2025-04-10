import pytest
from datetime import datetime
from src.compliance_engine.compliance_processor import ComplianceProcessor

@pytest.fixture
def compliance_processor():
    return ComplianceProcessor()

@pytest.fixture
def sample_scan_results():
    return {
        'aws': {
            'iam': {
                'service': 'IAM',
                'timestamp': datetime.utcnow().isoformat(),
                'findings': {
                    'password_policy': {
                        'minimum_length': True,
                        'requires_symbols': True,
                        'requires_numbers': True,
                        'requires_uppercase': True,
                        'requires_lowercase': True,
                        'expires_passwords': True,
                        'prevents_reuse': True
                    },
                    'root_account': {
                        'access_key_active': False,
                        'mfa_active': True,
                        'last_used': None
                    },
                    'users_mfa_status': [
                        {'username': 'user1', 'mfa_enabled': True},
                        {'username': 'user2', 'mfa_enabled': True}
                    ],
                    'access_keys': {
                        'access_keys': [
                            {
                                'username': 'user1',
                                'key_id': 'AKIA...',
                                'created_date': '2023-01-01T00:00:00Z',
                                'status': 'Active'
                            }
                        ]
                    }
                }
            },
            's3': {
                'service': 'S3',
                'timestamp': datetime.utcnow().isoformat(),
                'findings': [
                    {
                        'bucket_name': 'test-bucket',
                        'encryption': {'encrypted': True, 'type': 'AES256'},
                        'public_access': {
                            'block_public_acls': True,
                            'block_public_policy': True,
                            'ignore_public_acls': True,
                            'restrict_public_buckets': True
                        },
                        'logging': {'logging_enabled': True}
                    }
                ]
            }
        }
    }

def test_process_scan_results(compliance_processor, sample_scan_results):
    """Test processing of scan results"""
    frameworks = ['CIS', 'HIPAA', 'PCI', 'SOC2']
    results = compliance_processor.process_scan_results(sample_scan_results, frameworks)
    
    assert 'timestamp' in results
    assert 'evaluations' in results
    assert all(framework in results['evaluations'] for framework in frameworks)

def test_cis_compliance_evaluation(compliance_processor, sample_scan_results):
    """Test CIS compliance evaluation"""
    results = compliance_processor.process_scan_results(sample_scan_results, ['CIS'])
    cis_results = results['evaluations']['CIS']
    
    assert cis_results['framework'] == 'CIS'
    assert cis_results['version'] == '1.4.0'
    assert '1.1' in cis_results['controls']
    assert '1.2' in cis_results['controls']
    assert cis_results['controls']['1.1']['status'] == 'PASS'
    assert cis_results['controls']['1.2']['status'] == 'PASS'

def test_hipaa_compliance_evaluation(compliance_processor, sample_scan_results):
    """Test HIPAA compliance evaluation"""
    results = compliance_processor.process_scan_results(sample_scan_results, ['HIPAA'])
    hipaa_results = results['evaluations']['HIPAA']
    
    assert hipaa_results['framework'] == 'HIPAA'
    assert 'access_control' in hipaa_results['controls']
    assert 'encryption' in hipaa_results['controls']
    assert hipaa_results['controls']['access_control']['requirements']['unique_user_identification']['status'] == 'PASS'

def test_pci_compliance_evaluation(compliance_processor, sample_scan_results):
    """Test PCI-DSS compliance evaluation"""
    results = compliance_processor.process_scan_results(sample_scan_results, ['PCI'])
    pci_results = results['evaluations']['PCI']
    
    assert pci_results['framework'] == 'PCI-DSS'
    assert pci_results['version'] == '3.2.1'
    assert 'req_3' in pci_results['controls']
    assert 'req_7' in pci_results['controls']

def test_soc2_compliance_evaluation(compliance_processor, sample_scan_results):
    """Test SOC2 compliance evaluation"""
    results = compliance_processor.process_scan_results(sample_scan_results, ['SOC2'])
    soc2_results = results['evaluations']['SOC2']
    
    assert soc2_results['framework'] == 'SOC2'
    assert 'CC6.1' in soc2_results['controls']
    assert 'CC6.7' in soc2_results['controls']
    assert soc2_results['controls']['CC6.1']['status'] == 'PASS'
    assert soc2_results['controls']['CC6.7']['status'] == 'PASS'

def test_invalid_framework(compliance_processor, sample_scan_results):
    """Test handling of invalid compliance framework"""
    results = compliance_processor.process_scan_results(sample_scan_results, ['INVALID'])
    assert 'INVALID' not in results['evaluations']

def test_empty_scan_results(compliance_processor):
    """Test handling of empty scan results"""
    empty_results = {}
    results = compliance_processor.process_scan_results(empty_results, ['CIS'])
    cis_results = results['evaluations']['CIS']
    
    assert cis_results['controls'] == {} 