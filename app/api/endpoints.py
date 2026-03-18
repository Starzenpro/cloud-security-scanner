from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os
import asyncio
from datetime import datetime

from app.scanner.aws_scanner import AWSScanner
from app.scanner.azure_scanner import AzureScanner
from app.scanner.rules_engine import SecurityRulesEngine
from app.scanner.reporter import PDFReporter

app = FastAPI(
    title="Multi-Cloud Security Scanner",
    description="Scan AWS and Azure for security misconfigurations",
    version="1.0.0"
)

# Enable CORS for Streamlit
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

rules_engine = SecurityRulesEngine()
reporter = PDFReporter()
scan_history = []

class AWSCredentials(BaseModel):
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    region: str = "us-east-1"

class AzureCredentials(BaseModel):
    subscription_id: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: str
    provider: str
    timestamp: str
    total_findings: int
    risk_score: float
    risk_level: str
    summary: Dict[str, Any]

@app.get("/")
async def root():
    return {
        "service": "Multi-Cloud Security Scanner",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/scan/aws")
async def scan_aws(credentials: AWSCredentials):
    try:
        scanner = AWSScanner(
            aws_access_key=credentials.aws_access_key,
            aws_secret_key=credentials.aws_secret_key,
            region=credentials.region
        )
        results = scanner.scan_all()
        risk_score = rules_engine.calculate_risk_score(results['findings'])
        risk_level = rules_engine.get_risk_level(risk_score)

        scan_id = f"aws_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scan_history.append({
            'scan_id': scan_id,
            'provider': 'AWS',
            'results': results,
            'risk_score': risk_score,
            'risk_level': risk_level
        })

        return {
            'scan_id': scan_id,
            'provider': 'AWS',
            'timestamp': results['metadata']['scan_time'],
            'total_findings': results['total_findings'],
            'risk_score': risk_score,
            'risk_level': risk_level,
            'summary': results['summary']
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/azure")
async def scan_azure(credentials: AzureCredentials):
    try:
        scanner = AzureScanner(
            subscription_id=credentials.subscription_id
        )
        results = scanner.scan_all()
        risk_score = rules_engine.calculate_risk_score(results['findings'])
        risk_level = rules_engine.get_risk_level(risk_score)

        scan_id = f"azure_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scan_history.append({
            'scan_id': scan_id,
            'provider': 'Azure',
            'results': results,
            'risk_score': risk_score,
            'risk_level': risk_level
        })

        return {
            'scan_id': scan_id,
            'provider': 'Azure',
            'timestamp': results['metadata']['scan_time'],
            'total_findings': results['total_findings'],
            'risk_score': risk_score,
            'risk_level': risk_level,
            'summary': results['summary']
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/{scan_id}/report")
async def generate_report(scan_id: str):
    scan = next((s for s in scan_history if s['scan_id'] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        pdf_path = reporter.generate_report(
            scan['results'],
            rules_engine,
            provider=scan['provider']
        )
        return {
            'scan_id': scan_id,
            'report_path': pdf_path,
            'message': 'Report generated'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scans")
async def list_scans():
    return {
        'total_scans': len(scan_history),
        'recent_scans': [
            {
                'scan_id': s['scan_id'],
                'provider': s['provider'],
                'total_findings': s['results']['total_findings'],
                'risk_level': s['risk_level']
            }
            for s in scan_history[-5:]
        ]
    }
