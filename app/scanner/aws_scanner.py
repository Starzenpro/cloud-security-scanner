import boto3
from botocore.exceptions import ClientError
import json
from datetime import datetime, timedelta

from app.scanner.base_scanner import BaseCloudScanner

class AWSScanner(BaseCloudScanner):
    """
    AWS Security Scanner - Checks for misconfigurations across AWS services.
    """

    def __init__(self, aws_access_key=None, aws_secret_key=None, region='us-east-1'):
        super().__init__()
        self.scan_metadata['provider'] = 'AWS'
        self.scan_metadata['region'] = region
        self.scan_metadata['scan_time'] = datetime.now().isoformat()

        if aws_access_key and aws_secret_key:
            self.session = boto3.Session(
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=region
            )
        else:
            self.session = boto3.Session(region_name=region)

        # Get account ID
        try:
            sts = self.session.client('sts')
            self.scan_metadata['account_id'] = sts.get_caller_identity()['Account']
        except:
            self.scan_metadata['account_id'] = 'unknown'

    def authenticate(self):
        pass

    def scan_all(self):
        """Run all AWS security scans."""
        print("🔍 Starting AWS Security Scan...")
        self.findings = []

        self.scan_s3()
        self.scan_ec2()
        self.scan_iam()

        return self.get_results()

    def scan_s3(self):
        """Scan S3 buckets."""
        try:
            s3 = self.session.client('s3')
            buckets = s3.list_buckets()

            for bucket in buckets['Buckets']:
                bucket_name = bucket['Name']

                # Check bucket ACLs for public access
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        if 'URI' in grantee and 'AllUsers' in grantee['URI']:
                            self.add_finding(
                                service='S3',
                                resource=bucket_name,
                                issue='Public bucket - world readable via ACL',
                                severity='CRITICAL',
                                recommendation='Block public access and review bucket policies',
                                compliance=['CIS 2.1.2']
                            )
                except Exception as e:
                    print(f"Error checking ACL for {bucket_name}: {e}")

                # Check encryption
                try:
                    s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError:
                    self.add_finding(
                        service='S3',
                        resource=bucket_name,
                        issue='Default encryption not enabled',
                        severity='HIGH',
                        recommendation='Enable default encryption',
                        compliance=['CIS 2.1.1']
                    )

        except Exception as e:
            print(f"Error scanning S3: {e}")

    def scan_ec2(self):
        """Scan EC2 security groups."""
        try:
            ec2 = self.session.client('ec2')
            security_groups = ec2.describe_security_groups()

            for sg in security_groups['SecurityGroups']:
                sg_name = sg['GroupName']
                sg_id = sg['GroupId']

                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 'all')
                            
                            severity = 'CRITICAL'
                            if from_port in [22, 3389]:
                                issue = f"SSH/RDP (port {from_port}) open to world"
                            elif from_port in [80, 443]:
                                issue = f"Web port (port {from_port}) open to world"
                                severity = 'MEDIUM'
                            else:
                                issue = f"Port {from_port} open to world"

                            self.add_finding(
                                service='EC2',
                                resource=f"{sg_name} ({sg_id})",
                                issue=issue,
                                severity=severity,
                                recommendation='Restrict inbound rules to specific IP ranges',
                                compliance=['CIS 4.1.1']
                            )
        except Exception as e:
            print(f"Error scanning EC2: {e}")

    def scan_iam(self):
        """Scan IAM users."""
        try:
            iam = self.session.client('iam')

            # Check if root MFA is enabled
            try:
                root_creds = iam.get_account_summary()
                if root_creds['SummaryMap'].get('AccountMFAEnabled', 0) == 0:
                    self.add_finding(
                        service='IAM',
                        resource='Root User',
                        issue='Root user does not have MFA enabled',
                        severity='CRITICAL',
                        recommendation='Enable MFA for root user immediately',
                        compliance=['CIS 1.1.2']
                    )
            except:
                pass

            # Check IAM users for MFA
            users = iam.list_users()
            for user in users['Users']:
                username = user['UserName']
                try:
                    mfa = iam.list_mfa_devices(UserName=username)
                    if not mfa['MFADevices']:
                        self.add_finding(
                            service='IAM',
                            resource=username,
                            issue='MFA not enabled for user',
                            severity='HIGH',
                            recommendation='Enable MFA for all users',
                            compliance=['CIS 1.2.1']
                        )
                except:
                    pass

        except Exception as e:
            print(f"Error scanning IAM: {e}")
