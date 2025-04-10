from typing import Dict, List, Any
import yaml
import json
import logging
from datetime import datetime
from pathlib import Path

class PolicyManager:
    """Manages custom security policies and compliance requirements"""
    
    def __init__(self, policy_dir: str = "config/policies"):
        self.policy_dir = Path(policy_dir)
        self.logger = logging.getLogger(__name__)
        self.policies = self._load_policies()

    def _load_policies(self) -> Dict[str, Any]:
        """Load all policy definitions from the policy directory"""
        policies = {}
        try:
            for policy_file in self.policy_dir.glob("*.yaml"):
                with open(policy_file, 'r') as f:
                    policy_name = policy_file.stem
                    policies[policy_name] = yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Error loading policies: {str(e)}")
            raise
        return policies

    def get_policy_requirements(self, framework: str) -> Dict[str, Any]:
        """Get policy requirements for a specific compliance framework"""
        try:
            if framework in self.policies:
                return self.policies[framework]
            self.logger.warning(f"No policy found for framework: {framework}")
            return {}
        except Exception as e:
            self.logger.error(f"Error getting policy requirements: {str(e)}")
            raise

    def validate_compliance(self, scan_results: Dict[str, Any], 
                          framework: str) -> Dict[str, Any]:
        """Validate scan results against policy requirements"""
        try:
            if framework not in self.policies:
                return {
                    'framework': framework,
                    'status': 'UNKNOWN',
                    'error': f'No policy defined for framework {framework}'
                }

            policy = self.policies[framework]
            validation_results = {
                'framework': framework,
                'timestamp': datetime.utcnow().isoformat(),
                'requirements': {}
            }

            for requirement, rules in policy.get('requirements', {}).items():
                validation_results['requirements'][requirement] = \
                    self._validate_requirement(scan_results, rules)

            validation_results['status'] = self._calculate_overall_status(
                validation_results['requirements']
            )

            return validation_results
        except Exception as e:
            self.logger.error(f"Error validating compliance: {str(e)}")
            raise

    def _validate_requirement(self, scan_results: Dict[str, Any], 
                            rules: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a single requirement against scan results"""
        result = {
            'status': 'PASS',
            'findings': []
        }

        try:
            for rule in rules:
                finding = self._evaluate_rule(scan_results, rule)
                if finding:
                    result['findings'].append(finding)
                    if finding['severity'] in ['HIGH', 'CRITICAL']:
                        result['status'] = 'FAIL'
        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = str(e)

        return result

    def _evaluate_rule(self, scan_results: Dict[str, Any], 
                      rule: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a single rule against scan results"""
        try:
            service = rule.get('service')
            check = rule.get('check')
            expected = rule.get('expected')
            severity = rule.get('severity', 'MEDIUM')

            if not all([service, check, expected]):
                raise ValueError("Invalid rule definition")

            actual = self._get_value_from_results(scan_results, service, check)
            if actual != expected:
                return {
                    'rule': rule.get('name', 'Unnamed Rule'),
                    'severity': severity,
                    'expected': expected,
                    'actual': actual,
                    'message': rule.get('message', 'Rule validation failed')
                }
            return None
        except Exception as e:
            self.logger.error(f"Error evaluating rule: {str(e)}")
            return {
                'rule': rule.get('name', 'Unnamed Rule'),
                'severity': 'HIGH',
                'error': str(e)
            }

    def _get_value_from_results(self, results: Dict[str, Any], 
                              service: str, check: str) -> Any:
        """Extract a specific value from scan results using dot notation"""
        try:
            current = results
            for key in check.split('.'):
                current = current[key]
            return current
        except (KeyError, TypeError):
            return None

    def _calculate_overall_status(self, requirements: Dict[str, Any]) -> str:
        """Calculate overall compliance status based on requirements"""
        if not requirements:
            return 'UNKNOWN'

        statuses = [req['status'] for req in requirements.values()]
        
        if 'ERROR' in statuses:
            return 'ERROR'
        if 'FAIL' in statuses:
            return 'FAIL'
        if all(status == 'PASS' for status in statuses):
            return 'PASS'
        return 'PARTIAL'

    def create_policy(self, framework: str, policy_definition: Dict[str, Any]) -> bool:
        """Create a new policy definition"""
        try:
            policy_file = self.policy_dir / f"{framework.lower()}.yaml"
            with open(policy_file, 'w') as f:
                yaml.dump(policy_definition, f)
            self.policies[framework] = policy_definition
            return True
        except Exception as e:
            self.logger.error(f"Error creating policy: {str(e)}")
            return False

    def update_policy(self, framework: str, 
                     policy_updates: Dict[str, Any]) -> bool:
        """Update an existing policy definition"""
        try:
            if framework not in self.policies:
                return False

            current_policy = self.policies[framework]
            updated_policy = self._merge_policy_updates(current_policy, policy_updates)
            
            policy_file = self.policy_dir / f"{framework.lower()}.yaml"
            with open(policy_file, 'w') as f:
                yaml.dump(updated_policy, f)
            
            self.policies[framework] = updated_policy
            return True
        except Exception as e:
            self.logger.error(f"Error updating policy: {str(e)}")
            return False

    def _merge_policy_updates(self, current: Dict[str, Any], 
                            updates: Dict[str, Any]) -> Dict[str, Any]:
        """Merge policy updates with current policy"""
        merged = current.copy()
        
        for key, value in updates.items():
            if isinstance(value, dict) and key in merged:
                merged[key] = self._merge_policy_updates(merged[key], value)
            else:
                merged[key] = value
        
        return merged

    def export_policy(self, framework: str, format: str = 'yaml') -> str:
        """Export policy definition in specified format"""
        try:
            if framework not in self.policies:
                raise ValueError(f"No policy found for framework: {framework}")

            policy = self.policies[framework]
            
            if format.lower() == 'json':
                return json.dumps(policy, indent=2)
            elif format.lower() == 'yaml':
                return yaml.dump(policy)
            else:
                raise ValueError(f"Unsupported format: {format}")
        except Exception as e:
            self.logger.error(f"Error exporting policy: {str(e)}")
            raise 