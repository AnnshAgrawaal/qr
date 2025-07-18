from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from enum import Enum
import cv2
import numpy as np
from pyzbar import pyzbar
import re
import base64
from io import BytesIO
from PIL import Image
import urllib.parse
import logging
import hashlib
import json
from dataclasses import dataclass
from collections import defaultdict
import sqlite3
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="UPI QR Code Scanner API with Fraud Detection",
    description="API to scan UPI QR codes, extract account details, and report fraud",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
DATABASE_FILE = "fraud_reports.db"

def init_database():
    """Initialize SQLite database for fraud reports"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Create fraud_reports table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS fraud_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_hash TEXT NOT NULL,
        vpa TEXT,
        phone_number TEXT,
        reported_name TEXT,
        fraud_type TEXT NOT NULL,
        description TEXT,
        reporter_ip TEXT,
        reporter_fingerprint TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        verified BOOLEAN DEFAULT FALSE,
        severity INTEGER DEFAULT 1
    )
    ''')
    
    # Create account_identifiers table for linking different identifiers
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS account_identifiers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_hash TEXT NOT NULL,
        identifier_type TEXT NOT NULL,
        identifier_value TEXT NOT NULL,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(account_hash, identifier_type, identifier_value)
    )
    ''')
    
    # Create account_metadata table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS account_metadata (
        account_hash TEXT PRIMARY KEY,
        known_names TEXT,
        risk_score INTEGER DEFAULT 0,
        total_reports INTEGER DEFAULT 0,
        verified_reports INTEGER DEFAULT 0,
        first_reported DATETIME,
        last_reported DATETIME,
        status TEXT DEFAULT 'active'
    )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_database()

# Enums and Models
class FraudType(str, Enum):
    FAKE_PAYMENT = "fake_payment"
    PHISHING = "phishing"
    SCAM_CALL = "scam_call"
    UNAUTHORIZED_TRANSACTION = "unauthorized_transaction"
    FAKE_MERCHANT = "fake_merchant"
    INVESTMENT_FRAUD = "investment_fraud"
    LOTTERY_SCAM = "lottery_scam"
    OTHER = "other"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class UPIDetails(BaseModel):
    pa: Optional[str] = None  # Payment Address (VPA)
    pn: Optional[str] = None  # Payee Name
    mc: Optional[str] = None  # Merchant Category Code
    tr: Optional[str] = None  # Transaction Reference
    tn: Optional[str] = None  # Transaction Note
    am: Optional[str] = None  # Amount
    cu: Optional[str] = None  # Currency
    url: Optional[str] = None  # UPI URL
    raw_data: Optional[str] = None

class FraudReport(BaseModel):
    vpa: Optional[str] = None
    phone_number: Optional[str] = None
    reported_name: Optional[str] = None
    fraud_type: FraudType
    description: str = Field(min_length=10, max_length=1000)
    reporter_fingerprint: Optional[str] = None
    
    @validator('vpa', 'phone_number', pre=True)
    def at_least_one_identifier(cls, v, values):
        if not values.get('vpa') and not values.get('phone_number') and not v:
            raise ValueError('Either VPA or phone number must be provided')
        return v

class FraudAlert(BaseModel):
    account_hash: str
    risk_level: RiskLevel
    total_reports: int
    verified_reports: int
    common_fraud_types: List[str]
    warning_message: str
    last_reported: datetime
    known_names: List[str]

class ScanResponse(BaseModel):
    success: bool
    message: str
    data: Optional[UPIDetails] = None
    qr_type: Optional[str] = None
    fraud_alert: Optional[FraudAlert] = None

class AccountIdentifier:
    """Utility class to handle account identification and linking"""
    
    @staticmethod
    def generate_account_hash(*identifiers) -> str:
        """Generate a consistent hash for an account using multiple identifiers"""
        # Clean and normalize identifiers
        clean_identifiers = []
        for identifier in identifiers:
            if identifier:
                # Remove common variations and normalize
                clean_id = str(identifier).lower().strip()
                if '@' in clean_id:  # VPA
                    clean_id = clean_id.replace(' ', '')
                elif clean_id.startswith('+91'):  # Phone number
                    clean_id = clean_id.replace('+91', '').replace(' ', '').replace('-', '')
                elif clean_id.isdigit() and len(clean_id) == 10:  # Indian mobile number
                    clean_id = clean_id
                clean_identifiers.append(clean_id)
        
        if not clean_identifiers:
            raise ValueError("No valid identifiers provided")
        
        # Sort to ensure consistent hash regardless of order
        clean_identifiers.sort()
        combined = '|'.join(clean_identifiers)
        return hashlib.sha256(combined.encode()).hexdigest()
    
    @staticmethod
    def link_identifiers(account_hash: str, identifiers: dict):
        """Link different identifiers to the same account"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        for id_type, id_value in identifiers.items():
            if id_value:
                cursor.execute('''
                INSERT OR REPLACE INTO account_identifiers 
                (account_hash, identifier_type, identifier_value, last_seen)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ''', (account_hash, id_type, str(id_value)))
        
        conn.commit()
        conn.close()

class FraudDetectionService:
    """Service to handle fraud detection and reporting"""
    
    def __init__(self):
        self.risk_thresholds = {
            'low': 1,
            'medium': 3,
            'high': 5,
            'critical': 10
        }
    
    def calculate_risk_score(self, total_reports: int, verified_reports: int, 
                           recent_reports: int) -> int:
        """Calculate risk score based on various factors"""
        base_score = total_reports
        verification_bonus = verified_reports * 2
        recency_bonus = recent_reports * 1.5
        
        return int(base_score + verification_bonus + recency_bonus)
    
    def get_risk_level(self, risk_score: int) -> RiskLevel:
        """Determine risk level based on score"""
        if risk_score >= self.risk_thresholds['critical']:
            return RiskLevel.CRITICAL
        elif risk_score >= self.risk_thresholds['high']:
            return RiskLevel.HIGH
        elif risk_score >= self.risk_thresholds['medium']:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def check_fraud_status(self, account_hash: str) -> Optional[FraudAlert]:
        """Check if an account has fraud reports"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Get account metadata
        cursor.execute('''
        SELECT total_reports, verified_reports, known_names, 
               risk_score, last_reported, first_reported
        FROM account_metadata 
        WHERE account_hash = ?
        ''', (account_hash,))
        
        metadata = cursor.fetchone()
        if not metadata or metadata[0] == 0:
            conn.close()
            return None
        
        total_reports, verified_reports, known_names, risk_score, last_reported, first_reported = metadata
        
        # Get recent reports (last 30 days)
        cursor.execute('''
        SELECT COUNT(*) FROM fraud_reports 
        WHERE account_hash = ? AND timestamp > datetime('now', '-30 days')
        ''', (account_hash,))
        recent_reports = cursor.fetchone()[0]
        
        # Get common fraud types
        cursor.execute('''
        SELECT fraud_type, COUNT(*) as count
        FROM fraud_reports 
        WHERE account_hash = ?
        GROUP BY fraud_type
        ORDER BY count DESC
        LIMIT 3
        ''', (account_hash,))
        
        fraud_types = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        
        # Update risk score
        current_risk_score = self.calculate_risk_score(total_reports, verified_reports, recent_reports)
        risk_level = self.get_risk_level(current_risk_score)
        
        # Generate warning message
        warning_messages = {
            RiskLevel.LOW: f"This account has {total_reports} report(s). Exercise caution.",
            RiskLevel.MEDIUM: f"This account has {total_reports} reports including {verified_reports} verified. Be careful.",
            RiskLevel.HIGH: f"⚠️ HIGH RISK: This account has {total_reports} reports. Avoid transactions.",
            RiskLevel.CRITICAL: f"🚨 CRITICAL: This account has {total_reports} reports and is flagged as dangerous. DO NOT TRANSACT."
        }
        
        return FraudAlert(
            account_hash=account_hash,
            risk_level=risk_level,
            total_reports=total_reports,
            verified_reports=verified_reports,
            common_fraud_types=fraud_types,
            warning_message=warning_messages[risk_level],
            last_reported=datetime.fromisoformat(last_reported) if last_reported else datetime.now(),
            known_names=json.loads(known_names) if known_names else []
        )
    
    def submit_fraud_report(self, report: FraudReport, reporter_ip: str) -> bool:
        """Submit a fraud report"""
        try:
            # Generate account hash
            identifiers = []
            if report.vpa:
                identifiers.append(report.vpa)
            if report.phone_number:
                identifiers.append(report.phone_number)
            
            account_hash = AccountIdentifier.generate_account_hash(*identifiers)
            
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            
            # Insert fraud report
            cursor.execute('''
            INSERT INTO fraud_reports 
            (account_hash, vpa, phone_number, reported_name, fraud_type, 
             description, reporter_ip, reporter_fingerprint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (account_hash, report.vpa, report.phone_number, report.reported_name,
                  report.fraud_type, report.description, reporter_ip, 
                  report.reporter_fingerprint))
            
            # Update account metadata
            cursor.execute('''
            INSERT OR IGNORE INTO account_metadata (account_hash, total_reports, first_reported)
            VALUES (?, 0, CURRENT_TIMESTAMP)
            ''', (account_hash,))
            
            # Update metadata counts
            cursor.execute('''
            UPDATE account_metadata 
            SET total_reports = total_reports + 1,
                last_reported = CURRENT_TIMESTAMP,
                known_names = CASE 
                    WHEN known_names IS NULL THEN json_array(?)
                    WHEN json_extract(known_names, '$') NOT LIKE '%' || ? || '%' THEN json_insert(known_names, '$[#]', ?)
                    ELSE known_names
                END
            WHERE account_hash = ?
            ''', (report.reported_name or '', report.reported_name or '', report.reported_name or '', account_hash))
            
            # Link identifiers
            identifiers_dict = {}
            if report.vpa:
                identifiers_dict['vpa'] = report.vpa
            if report.phone_number:
                identifiers_dict['phone'] = report.phone_number
            
            AccountIdentifier.link_identifiers(account_hash, identifiers_dict)
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error submitting fraud report: {str(e)}")
            return False

# Initialize services
fraud_service = FraudDetectionService()

# Your existing UPIQRScanner class remains the same
class UPIQRScanner:
    def __init__(self):
        self.upi_patterns = [
            r'upi://pay\?(.+)',
            r'paytm://pay\?(.+)',
            r'phonepe://pay\?(.+)',
            r'gpay://pay\?(.+)',
            r'bhim://pay\?(.+)'
        ]
    
    def decode_qr_code(self, image_data: bytes) -> Optional[str]:
        """Decode QR code from image bytes"""
        try:
            nparr = np.frombuffer(image_data, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if img is None:
                logger.error("Could not decode image")
                return None
            
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            qr_codes = pyzbar.decode(gray)
            
            if not qr_codes:
                thresh = cv2.adaptiveThreshold(
                    gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                    cv2.THRESH_BINARY, 11, 2
                )
                qr_codes = pyzbar.decode(thresh)
            
            if qr_codes:
                return qr_codes[0].data.decode('utf-8')
            
            return None
            
        except Exception as e:
            logger.error(f"Error decoding QR code: {str(e)}")
            return None
    
    def parse_upi_url(self, qr_data: str) -> UPIDetails:
        """Parse UPI URL and extract parameters"""
        upi_details = UPIDetails(raw_data=qr_data)
        
        for pattern in self.upi_patterns:
            match = re.match(pattern, qr_data, re.IGNORECASE)
            if match:
                params_string = match.group(1)
                break
        else:
            if 'pa=' in qr_data:
                params_string = qr_data.split('?', 1)[-1] if '?' in qr_data else qr_data
            else:
                return upi_details
        
        try:
            params = urllib.parse.parse_qs(params_string)
            
            upi_details.pa = params.get('pa', [None])[0]
            upi_details.pn = params.get('pn', [None])[0]
            upi_details.mc = params.get('mc', [None])[0]
            upi_details.tr = params.get('tr', [None])[0]
            upi_details.tn = params.get('tn', [None])[0]
            upi_details.am = params.get('am', [None])[0]
            upi_details.cu = params.get('cu', [None])[0]
            upi_details.url = qr_data
            
            if upi_details.pn:
                upi_details.pn = urllib.parse.unquote(upi_details.pn)
            if upi_details.tn:
                upi_details.tn = urllib.parse.unquote(upi_details.tn)
                
        except Exception as e:
            logger.error(f"Error parsing UPI parameters: {str(e)}")
        
        return upi_details

# Initialize scanner
scanner = UPIQRScanner()

# Enhanced endpoints
@app.get("/")
async def root():
    return {"message": "UPI QR Code Scanner API with Fraud Detection", "version": "2.0.0"}

@app.post("/scan-qr", response_model=ScanResponse)
async def scan_qr_code(file: UploadFile = File(...)):
    """Scan UPI QR code and check for fraud alerts"""
    try:
        if not file.content_type.startswith('image/'):
            raise HTTPException(
                status_code=400, 
                detail="Invalid file type. Please upload an image file."
            )
        
        image_data = await file.read()
        qr_data = scanner.decode_qr_code(image_data)
        
        if not qr_data:
            return ScanResponse(
                success=False,
                message="No QR code found in the image",
                qr_type="none"
            )
        
        upi_details = scanner.parse_upi_url(qr_data)
        
        if not upi_details.pa:
            return ScanResponse(
                success=False,
                message="QR code found but it's not a UPI payment code",
                qr_type="non-upi",
                data=upi_details
            )
        
        # Check for fraud alerts
        fraud_alert = None
        if upi_details.pa:
            try:
                account_hash = AccountIdentifier.generate_account_hash(upi_details.pa)
                fraud_alert = fraud_service.check_fraud_status(account_hash)
            except Exception as e:
                logger.warning(f"Error checking fraud status: {str(e)}")
        
        return ScanResponse(
            success=True,
            message="UPI QR code scanned successfully",
            qr_type="upi",
            data=upi_details,
            fraud_alert=fraud_alert
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing QR code: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.post("/report-fraud")
async def report_fraud(report: FraudReport, request: dict = None):
    """Submit a fraud report"""
    try:
        reporter_ip = request.get('client_ip', '127.0.0.1') if request else '127.0.0.1'
        
        success = fraud_service.submit_fraud_report(report, reporter_ip)
        
        if success:
            return {
                "success": True,
                "message": "Fraud report submitted successfully. Thank you for keeping the community safe!"
            }
        else:
            raise HTTPException(
                status_code=500,
                detail="Failed to submit fraud report"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting fraud report: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/fraud-stats")
async def get_fraud_stats():
    """Get fraud reporting statistics"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Get total reports
        cursor.execute('SELECT COUNT(*) FROM fraud_reports')
        total_reports = cursor.fetchone()[0]
        
        # Get reports by type
        cursor.execute('''
        SELECT fraud_type, COUNT(*) as count
        FROM fraud_reports 
        GROUP BY fraud_type
        ORDER BY count DESC
        ''')
        fraud_types = dict(cursor.fetchall())
        
        # Get recent reports (last 7 days)
        cursor.execute('''
        SELECT COUNT(*) FROM fraud_reports 
        WHERE timestamp > datetime('now', '-7 days')
        ''')
        recent_reports = cursor.fetchone()[0]
        
        # Get high-risk accounts
        cursor.execute('''
        SELECT COUNT(*) FROM account_metadata 
        WHERE risk_score >= 5
        ''')
        high_risk_accounts = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_reports": total_reports,
            "fraud_types": fraud_types,
            "recent_reports": recent_reports,
            "high_risk_accounts": high_risk_accounts
        }
        
    except Exception as e:
        logger.error(f"Error getting fraud stats: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "UPI QR Scanner API with Fraud Detection"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)