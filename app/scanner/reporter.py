from datetime import datetime
import json
import os

class PDFReporter:
    """
    Generate security reports (simplified console version).
    """

    def generate_report(self, scan_results, rules_engine, provider='AWS', output_path='data/reports'):
        """Generate a simple text report."""
        os.makedirs(output_path, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{output_path}/{provider}_scan_{timestamp}.txt"

        risk_score = rules_engine.calculate_risk_score(scan_results['findings'])
        summary = rules_engine.generate_executive_summary(scan_results['findings'], risk_score)

        with open(filename, 'w') as f:
            f.write(f"{provider} Cloud Security Scan Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Scan Time: {scan_results['metadata']['scan_time']}\n")
            f.write(f"Account: {scan_results['metadata'].get('account_id', 'N/A')}\n\n")
            f.write(f"Risk Score: {risk_score}/100 ({summary['risk_level']})\n")
            f.write(f"Total Findings: {summary['total_findings']}\n")
            f.write(f"  Critical: {summary['critical_count']}\n")
            f.write(f"  High: {summary['high_count']}\n")
            f.write(f"  Medium: {summary['medium_count']}\n")
            f.write(f"  Low: {summary['low_count']}\n\n")
            
            for finding in scan_results['findings']:
                f.write(f"[{finding['severity']}] {finding['service']}: {finding['issue']}\n")
                f.write(f"  Resource: {finding['resource']}\n")
                f.write(f"  Fix: {finding['recommendation']}\n\n")

        print(f"✅ Report saved to {filename}")
        return filename

    def generate_multi_cloud_report(self, findings, scan_id, results, output_path='data/reports'):
        """Generate a simple multi-cloud report."""
        os.makedirs(output_path, exist_ok=True)
        filename = f"{output_path}/multi_cloud_report_{scan_id}.txt"

        with open(filename, 'w') as f:
            f.write(f"Multi-Cloud Security Scan Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Scan ID: {scan_id}\n")
            f.write(f"Date: {datetime.now().isoformat()}\n\n")

            for provider, data in results.items():
                f.write(f"{provider.upper()} Findings: {data['total_findings']}\n")

        print(f"✅ Multi-cloud report saved to {filename}")
        return filename
