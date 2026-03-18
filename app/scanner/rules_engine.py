class SecurityRulesEngine:
    """
    Evaluates security findings and calculates risk scores.
    """

    def __init__(self):
        self.risk_weights = {
            'CRITICAL': 10.0,
            'HIGH': 7.0,
            'MEDIUM': 4.0,
            'LOW': 1.0
        }

    def calculate_risk_score(self, findings):
        """Calculate overall risk score (0-100)."""
        if not findings:
            return 0

        total_weight = 0
        max_possible = len(findings) * self.risk_weights['CRITICAL']

        for finding in findings:
            severity = finding.get('severity', 'LOW')
            weight = self.risk_weights.get(severity, 1.0)
            total_weight += weight

        risk_score = (total_weight / max_possible) * 100 if max_possible > 0 else 0
        return round(risk_score, 2)

    def get_risk_level(self, score):
        """Convert numeric score to risk level."""
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'

    def generate_executive_summary(self, findings, risk_score):
        """Generate executive summary."""
        critical = len([f for f in findings if f['severity'] == 'CRITICAL'])
        high = len([f for f in findings if f['severity'] == 'HIGH'])
        medium = len([f for f in findings if f['severity'] == 'MEDIUM'])
        low = len([f for f in findings if f['severity'] == 'LOW'])

        return {
            'risk_score': risk_score,
            'risk_level': self.get_risk_level(risk_score),
            'total_findings': len(findings),
            'critical_count': critical,
            'high_count': high,
            'medium_count': medium,
            'low_count': low
        }
