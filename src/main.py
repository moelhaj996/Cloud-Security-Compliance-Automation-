import argparse
import logging
import yaml
from typing import List, Dict, Any
from cloud_scanners.aws.aws_scanner import AWSSecurityScanner
from compliance_engine.compliance_processor import ComplianceProcessor
from alert_system.alert_manager import AlertManager

def setup_logging():
    """Configure logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Error loading config: {str(e)}")
        raise

def run_compliance_scan(clouds: List[str], config: Dict[str, Any]) -> Dict[str, Any]:
    """Run compliance scan on specified cloud providers"""
    scan_results = {}
    
    try:
        # AWS Scan
        if 'aws' in clouds:
            aws_scanner = AWSSecurityScanner(region=config['aws'].get('region', 'us-east-1'))
            scan_results['aws'] = {
                'iam': aws_scanner.scan_iam_compliance(),
                's3': aws_scanner.scan_s3_compliance()
            }
        
        # Azure Scan (placeholder)
        if 'azure' in clouds:
            logging.info("Azure scanning not yet implemented")
        
        # GCP Scan (placeholder)
        if 'gcp' in clouds:
            logging.info("GCP scanning not yet implemented")
        
        return scan_results
    except Exception as e:
        logging.error(f"Error during compliance scan: {str(e)}")
        raise

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description='Cloud Security Compliance Scanner')
    parser.add_argument('--clouds', nargs='+', default=['aws'],
                      help='Cloud providers to scan (aws, azure, gcp)')
    parser.add_argument('--config', default='config/config.yaml',
                      help='Path to configuration file')
    parser.add_argument('--frameworks', nargs='+', 
                      default=['CIS', 'HIPAA', 'PCI', 'SOC2'],
                      help='Compliance frameworks to evaluate')
    args = parser.parse_args()

    try:
        # Setup
        setup_logging()
        config = load_config(args.config)
        
        # Initialize components
        compliance_processor = ComplianceProcessor()
        alert_manager = AlertManager(config.get('alerts', {}))
        
        # Run scans
        logging.info(f"Starting compliance scan for: {', '.join(args.clouds)}")
        scan_results = run_compliance_scan(args.clouds, config)
        
        # Process results
        logging.info(f"Evaluating compliance for frameworks: {', '.join(args.frameworks)}")
        compliance_results = compliance_processor.process_scan_results(
            scan_results, args.frameworks
        )
        
        # Handle alerts
        alert_manager.process_compliance_results(compliance_results)
        
        logging.info("Compliance scan completed successfully")
        
    except Exception as e:
        logging.error(f"Error in compliance scanner: {str(e)}")
        raise

if __name__ == '__main__':
    main() 