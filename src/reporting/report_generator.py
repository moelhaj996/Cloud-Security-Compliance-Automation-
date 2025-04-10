from typing import Dict, List, Any
import json
import yaml
import csv
import logging
from datetime import datetime
from pathlib import Path
import jinja2
import markdown
import plotly.graph_objects as go
import pandas as pd

class ReportGenerator:
    """Generates compliance reports in various formats"""
    
    def __init__(self, template_dir: str = "config/templates"):
        self.template_dir = Path(template_dir)
        self.logger = logging.getLogger(__name__)
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.template_dir))
        )

    def generate_report(self, compliance_results: Dict[str, Any],
                       format: str = 'html',
                       output_file: str = None) -> str:
        """Generate compliance report in specified format"""
        try:
            if format.lower() == 'html':
                return self._generate_html_report(compliance_results, output_file)
            elif format.lower() == 'pdf':
                return self._generate_pdf_report(compliance_results, output_file)
            elif format.lower() == 'json':
                return self._generate_json_report(compliance_results, output_file)
            elif format.lower() == 'csv':
                return self._generate_csv_report(compliance_results, output_file)
            else:
                raise ValueError(f"Unsupported format: {format}")
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            raise

    def _generate_html_report(self, results: Dict[str, Any],
                            output_file: str = None) -> str:
        """Generate HTML report with interactive charts"""
        try:
            template = self.jinja_env.get_template('compliance_report.html')
            
            # Generate charts
            overview_chart = self._create_overview_chart(results)
            framework_charts = self._create_framework_charts(results)
            trend_chart = self._create_trend_chart(results)
            
            # Prepare report data
            report_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'results': results,
                'summary': self._generate_summary(results),
                'charts': {
                    'overview': overview_chart,
                    'frameworks': framework_charts,
                    'trend': trend_chart
                }
            }
            
            # Render HTML
            html_content = template.render(**report_data)
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(html_content)
            
            return html_content
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            raise

    def _generate_pdf_report(self, results: Dict[str, Any],
                           output_file: str = None) -> str:
        """Generate PDF report with charts and formatting"""
        try:
            # First generate HTML
            html_content = self._generate_html_report(results)
            
            # Convert HTML to PDF using WeasyPrint or similar
            if output_file:
                # Implementation depends on PDF generation library
                pass
            
            return output_file
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {str(e)}")
            raise

    def _generate_json_report(self, results: Dict[str, Any],
                            output_file: str = None) -> str:
        """Generate JSON report"""
        try:
            json_content = json.dumps(results, indent=2)
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(json_content)
            
            return json_content
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {str(e)}")
            raise

    def _generate_csv_report(self, results: Dict[str, Any],
                           output_file: str = None) -> str:
        """Generate CSV report"""
        try:
            # Flatten compliance results for CSV format
            rows = self._flatten_results(results)
            
            if output_file:
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
            
            return "\n".join([",".join(map(str, row.values())) for row in rows])
        except Exception as e:
            self.logger.error(f"Error generating CSV report: {str(e)}")
            raise

    def _create_overview_chart(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Create overview compliance chart"""
        try:
            frameworks = results.get('evaluations', {}).keys()
            statuses = ['PASS', 'FAIL', 'PARTIAL', 'ERROR']
            
            data = {status: [] for status in statuses}
            for framework in frameworks:
                framework_results = results['evaluations'][framework]
                status_count = self._count_control_statuses(framework_results)
                for status in statuses:
                    data[status].append(status_count.get(status, 0))
            
            fig = go.Figure(data=[
                go.Bar(name=status, x=list(frameworks), y=data[status])
                for status in statuses
            ])
            
            fig.update_layout(
                title='Compliance Overview by Framework',
                barmode='stack',
                xaxis_title='Framework',
                yaxis_title='Number of Controls'
            )
            
            return fig.to_json()
        except Exception as e:
            self.logger.error(f"Error creating overview chart: {str(e)}")
            return {}

    def _create_framework_charts(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Create detailed charts for each framework"""
        try:
            charts = {}
            for framework, data in results.get('evaluations', {}).items():
                status_count = self._count_control_statuses(data)
                
                fig = go.Figure(data=[go.Pie(
                    labels=list(status_count.keys()),
                    values=list(status_count.values())
                )])
                
                fig.update_layout(
                    title=f'{framework} Compliance Status',
                    showlegend=True
                )
                
                charts[framework] = fig.to_json()
            
            return charts
        except Exception as e:
            self.logger.error(f"Error creating framework charts: {str(e)}")
            return {}

    def _create_trend_chart(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Create compliance trend chart"""
        try:
            # This would typically use historical data
            # For now, we'll create a placeholder
            fig = go.Figure()
            fig.update_layout(
                title='Compliance Trend Over Time',
                xaxis_title='Date',
                yaxis_title='Compliance Score (%)'
            )
            
            return fig.to_json()
        except Exception as e:
            self.logger.error(f"Error creating trend chart: {str(e)}")
            return {}

    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of compliance results"""
        try:
            summary = {
                'timestamp': datetime.utcnow().isoformat(),
                'overall_status': self._calculate_overall_status(results),
                'framework_summary': {},
                'critical_findings': [],
                'recommendations': []
            }
            
            for framework, data in results.get('evaluations', {}).items():
                framework_summary = self._summarize_framework(framework, data)
                summary['framework_summary'][framework] = framework_summary
                summary['critical_findings'].extend(framework_summary['critical_findings'])
                summary['recommendations'].extend(framework_summary['recommendations'])
            
            return summary
        except Exception as e:
            self.logger.error(f"Error generating summary: {str(e)}")
            return {}

    def _calculate_overall_status(self, results: Dict[str, Any]) -> str:
        """Calculate overall compliance status"""
        try:
            statuses = []
            for framework_data in results.get('evaluations', {}).values():
                if 'status' in framework_data:
                    statuses.append(framework_data['status'])
            
            if not statuses:
                return 'UNKNOWN'
            if 'ERROR' in statuses:
                return 'ERROR'
            if 'FAIL' in statuses:
                return 'FAIL'
            if all(status == 'PASS' for status in statuses):
                return 'PASS'
            return 'PARTIAL'
        except Exception:
            return 'ERROR'

    def _summarize_framework(self, framework: str,
                           data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary for a specific framework"""
        try:
            critical_findings = []
            recommendations = []
            
            for control_id, control in data.get('controls', {}).items():
                if control.get('status') == 'FAIL':
                    finding = {
                        'framework': framework,
                        'control': control_id,
                        'title': control.get('title', 'Unknown Control'),
                        'severity': control.get('severity', 'MEDIUM')
                    }
                    critical_findings.append(finding)
                    
                    recommendation = {
                        'control': control_id,
                        'title': control.get('title', 'Unknown Control'),
                        'action': control.get('remediation', 'No remediation provided')
                    }
                    recommendations.append(recommendation)
            
            return {
                'status': data.get('status', 'UNKNOWN'),
                'total_controls': len(data.get('controls', {})),
                'passing_controls': sum(1 for c in data.get('controls', {}).values()
                                     if c.get('status') == 'PASS'),
                'critical_findings': critical_findings,
                'recommendations': recommendations
            }
        except Exception as e:
            self.logger.error(f"Error summarizing framework: {str(e)}")
            return {}

    def _count_control_statuses(self, data: Dict[str, Any]) -> Dict[str, int]:
        """Count the number of controls in each status"""
        try:
            status_count = {'PASS': 0, 'FAIL': 0, 'PARTIAL': 0, 'ERROR': 0}
            
            for control in data.get('controls', {}).values():
                status = control.get('status', 'ERROR')
                status_count[status] = status_count.get(status, 0) + 1
            
            return status_count
        except Exception:
            return {'ERROR': 1}

    def _flatten_results(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Flatten nested results structure for CSV format"""
        try:
            flattened = []
            
            for framework, data in results.get('evaluations', {}).items():
                for control_id, control in data.get('controls', {}).items():
                    row = {
                        'Framework': framework,
                        'Control_ID': control_id,
                        'Title': control.get('title', ''),
                        'Status': control.get('status', ''),
                        'Severity': control.get('severity', ''),
                        'Details': control.get('details', '')
                    }
                    flattened.append(row)
            
            return flattened
        except Exception as e:
            self.logger.error(f"Error flattening results: {str(e)}")
            return [] 