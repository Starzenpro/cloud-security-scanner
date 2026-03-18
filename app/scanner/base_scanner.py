from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any

class BaseCloudScanner(ABC):
    """
    Abstract base class for all cloud providers.
    Ensures consistent interface across AWS, Azure, GCP.
    """

    def __init__(self):
        self.findings = []
        self.scan_metadata = {
            'provider': None,
            'scan_time': None,
            'account_id': None,
            'region': None
        }

    @abstractmethod
    def authenticate(self):
        """Authenticate with cloud provider."""
        pass

    @abstractmethod
    def scan_all(self):
        """Run all security scans."""
        pass

    @abstractmethod
    def scan_storage(self):
        """Scan storage services (S3, Blob Storage)."""
        pass

    @abstractmethod
    def scan_compute(self):
        """Scan compute services (EC2, VMs)."""
        pass

    @abstractmethod
    def scan_networking(self):
        """Scan networking (Security Groups, NSGs)."""
        pass

    @abstractmethod
    def scan_identity(self):
        """Scan identity (IAM, Azure AD)."""
        pass

    @abstractmethod
    def scan_logging(self):
        """Scan logging (CloudTrail, Azure Monitor)."""
        pass

    @abstractmethod
    def scan_databases(self):
        """Scan databases (RDS, SQL, CosmosDB)."""
        pass

    def add_finding(self, service: str, resource: str, issue: str,
                   severity: str, recommendation: str, compliance: List[str] = None):
        """
        Add a security finding with standardized format.
        """
        finding = {
            'service': service,
            'resource': resource,
            'issue': issue,
            'severity': severity,
            'recommendation': recommendation,
            'compliance': compliance or []
        }
        self.findings.append(finding)
        return finding

    def get_results(self):
        """
        Return complete scan results.
        """
        return {
            'metadata': self.scan_metadata,
            'total_findings': len(self.findings),
            'findings': self.findings,
            'summary': self._generate_summary()
        }

    def _generate_summary(self):
        """
        Generate summary statistics from findings.
        Returns a dict with counts per severity and per service.
        """
        summary = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'by_service': {}
        }

        for finding in self.findings:
            severity = finding.get('severity', 'LOW')
            service = finding.get('service', 'Unknown')

            # Increment severity count
            summary[severity] = summary.get(severity, 0) + 1

            # Increment service count
            summary['by_service'][service] = summary['by_service'].get(service, 0) + 1

        return summary
