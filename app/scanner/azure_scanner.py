from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from datetime import datetime
import os

from app.scanner.base_scanner import BaseCloudScanner

class AzureScanner(BaseCloudScanner):
    """
    Azure Security Scanner - Simplified version.
    """

    def __init__(self, tenant_id=None, client_id=None, client_secret=None, subscription_id=None):
        super().__init__()
        self.scan_metadata['provider'] = 'Azure'
        self.scan_metadata['scan_time'] = datetime.now().isoformat()

        self.subscription_id = subscription_id or os.getenv('AZURE_SUBSCRIPTION_ID')
        self.credential = DefaultAzureCredential()
        self.scan_metadata['account_id'] = self.subscription_id

    def authenticate(self):
        pass

    def scan_all(self):
        """Run all Azure security scans."""
        print("🔍 Starting Azure Security Scan...")
        self.findings = []

        self.scan_storage()
        self.scan_networking()

        return self.get_results()

    def scan_storage(self):
        """Scan Azure Storage Accounts."""
        try:
            storage_client = StorageManagementClient(self.credential, self.subscription_id)
            accounts = storage_client.storage_accounts.list()

            for account in accounts:
                account_name = account.name

                # Check HTTPS enforcement
                if not account.enable_https_traffic_only:
                    self.add_finding(
                        service='Storage',
                        resource=account_name,
                        issue='HTTPS traffic not enforced',
                        severity='HIGH',
                        recommendation='Enable "Secure transfer required"',
                        compliance=['CIS 3.1']
                    )

                # Check public access
                if account.public_network_access == 'Enabled':
                    self.add_finding(
                        service='Storage',
                        resource=account_name,
                        issue='Public network access allowed',
                        severity='CRITICAL',
                        recommendation='Disable public network access',
                        compliance=['CIS 3.2']
                    )

        except Exception as e:
            print(f"Error scanning Azure Storage: {e}")

    def scan_networking(self):
        """Scan Azure Network Security Groups."""
        try:
            network_client = NetworkManagementClient(self.credential, self.subscription_id)
            nsgs = network_client.network_security_groups.list_all()

            for nsg in nsgs:
                nsg_name = nsg.name

                for rule in nsg.security_rules or []:
                    if rule.direction == 'Inbound' and rule.access == 'Allow':
                        for source in rule.source_address_prefixes or []:
                            if source in ['*', '0.0.0.0/0', 'Internet']:
                                port = rule.destination_port_range or 'any'
                                severity = 'CRITICAL' if port in ['22', '3389'] else 'HIGH'
                                
                                self.add_finding(
                                    service='Networking',
                                    resource=nsg_name,
                                    issue=f'Port {port} open to Internet',
                                    severity=severity,
                                    recommendation='Restrict NSG rules to specific IP ranges',
                                    compliance=['CIS 6.1']
                                )
        except Exception as e:
            print(f"Error scanning Azure Networking: {e}")
