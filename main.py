from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import cv2
import numpy as np
from pyzbar import pyzbar
import re
import base64
from io import BytesIO
from PIL import Image
import urllib.parse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="UPI QR Code Scanner API",
    description="API to scan UPI QR codes and extract account details",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://qr-xi-sage.vercel.app",  # Vercel domain
        "http://localhost:3000",             # For local development
        "http://localhost:8000",             # For local backend testing
        "http://127.0.0.1:3000",            # Alternative localhost
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Response models
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

class ScanResponse(BaseModel):
    success: bool
    message: str
    data: Optional[UPIDetails] = None
    qr_type: Optional[str] = None

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
            # Convert bytes to numpy array
            nparr = np.frombuffer(image_data, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if img is None:
                logger.error("Could not decode image")
                return None
            
            # Convert to grayscale for better QR detection
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            
            # Detect and decode QR codes
            qr_codes = pyzbar.decode(gray)
            
            if not qr_codes:
                # Try with different preprocessing
                # Apply adaptive threshold
                thresh = cv2.adaptiveThreshold(
                    gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                    cv2.THRESH_BINARY, 11, 2
                )
                qr_codes = pyzbar.decode(thresh)
            
            if qr_codes:
                # Return the first QR code data
                return qr_codes[0].data.decode('utf-8')
            
            return None
            
        except Exception as e:
            logger.error(f"Error decoding QR code: {str(e)}")
            return None
    
    def parse_upi_url(self, qr_data: str) -> UPIDetails:
        """Parse UPI URL and extract parameters"""
        upi_details = UPIDetails(raw_data=qr_data)
        
        # Check if it's a UPI URL
        for pattern in self.upi_patterns:
            match = re.match(pattern, qr_data, re.IGNORECASE)
            if match:
                params_string = match.group(1)
                break
        else:
            # If not a standard UPI URL, check if it contains UPI parameters
            if 'pa=' in qr_data:
                params_string = qr_data.split('?', 1)[-1] if '?' in qr_data else qr_data
            else:
                return upi_details
        
        # Parse parameters
        try:
            params = urllib.parse.parse_qs(params_string)
            
            # Extract UPI parameters
            upi_details.pa = params.get('pa', [None])[0]  # Payment Address
            upi_details.pn = params.get('pn', [None])[0]  # Payee Name
            upi_details.mc = params.get('mc', [None])[0]  # Merchant Category Code
            upi_details.tr = params.get('tr', [None])[0]  # Transaction Reference
            upi_details.tn = params.get('tn', [None])[0]  # Transaction Note
            upi_details.am = params.get('am', [None])[0]  # Amount
            upi_details.cu = params.get('cu', [None])[0]  # Currency
            upi_details.url = qr_data
            
            # URL decode the values
            if upi_details.pn:
                upi_details.pn = urllib.parse.unquote(upi_details.pn)
            if upi_details.tn:
                upi_details.tn = urllib.parse.unquote(upi_details.tn)
                
        except Exception as e:
            logger.error(f"Error parsing UPI parameters: {str(e)}")
        
        return upi_details
    
    def extract_account_info(self, upi_details: UPIDetails) -> Dict[str, Any]:
        """Extract readable account information"""
        account_info = {}
        
        if upi_details.pa:
            # Extract bank/provider info from VPA
            if '@' in upi_details.pa:
                username, domain = upi_details.pa.split('@', 1)
                account_info['vpa'] = upi_details.pa
                account_info['username'] = username
                account_info['provider'] = domain
                
                # Map common providers
                provider_map = {
                    'paytm': 'Paytm',
                    'ybl': 'PhonePe',
                    'okaxis': 'Axis Bank',
                    'okhdfc': 'HDFC Bank',
                    'okicici': 'ICICI Bank',
                    'oksbi': 'State Bank of India',
                    'ibl': 'IDBI Bank',
                    'cnrb': 'Canara Bank',
                    'upi': 'BHIM UPI'
                }
                
                account_info['provider_name'] = provider_map.get(domain, domain.upper())
        
        if upi_details.pn:
            account_info['payee_name'] = upi_details.pn
        
        if upi_details.mc:
            account_info['merchant_category'] = upi_details.mc
        
        if upi_details.am:
            account_info['amount'] = upi_details.am
            account_info['currency'] = upi_details.cu or 'INR'
        
        if upi_details.tn:
            account_info['transaction_note'] = upi_details.tn
        
        return account_info

# Initialize scanner
scanner = UPIQRScanner()

@app.get("/")
async def root():
    return {"message": "UPI QR Code Scanner API", "version": "1.0.0"}

@app.post("/scan-qr", response_model=ScanResponse)
async def scan_qr_code(file: UploadFile = File(...)):
    """
    Scan UPI QR code from uploaded image and extract account details
    """
    try:
        # Validate file type with None check
        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(
                status_code=400,
                detail="Invalid file type. Please upload an image file."
            )
        
        # Read image data
        image_data = await file.read()
        
        # Decode QR code
        qr_data = scanner.decode_qr_code(image_data)
        
        if not qr_data:
            return ScanResponse(
                success=False,
                message="No QR code found in the image",
                qr_type="none"
            )
        
        # Parse UPI data
        upi_details = scanner.parse_upi_url(qr_data)
        
        # Check if it's a UPI QR code
        if not upi_details.pa:
            return ScanResponse(
                success=False,
                message="QR code found but it's not a UPI payment code",
                qr_type="non-upi",
                data=upi_details
            )
        
        return ScanResponse(
            success=True,
            message="UPI QR code scanned successfully",
            qr_type="upi",
            data=upi_details
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing QR code: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.post("/scan-qr-base64", response_model=ScanResponse)
async def scan_qr_code_base64(image_data: dict):
    """
    Scan UPI QR code from base64 encoded image
    Expected format: {"image": "base64_string"}
    """
    try:
        if "image" not in image_data:
            raise HTTPException(
                status_code=400,
                detail="Missing 'image' field in request body"
            )
        
        # Decode base64 image
        try:
            image_bytes = base64.b64decode(image_data["image"])
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail="Invalid base64 image data"
            )
        
        # Decode QR code
        qr_data = scanner.decode_qr_code(image_bytes)
        
        if not qr_data:
            return ScanResponse(
                success=False,
                message="No QR code found in the image",
                qr_type="none"
            )
        
        # Parse UPI data
        upi_details = scanner.parse_upi_url(qr_data)
        
        # Check if it's a UPI QR code
        if not upi_details.pa:
            return ScanResponse(
                success=False,
                message="QR code found but it's not a UPI payment code",
                qr_type="non-upi",
                data=upi_details
            )
        
        return ScanResponse(
            success=True,
            message="UPI QR code scanned successfully",
            qr_type="upi",
            data=upi_details
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing QR code: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/account-info/{vpa}")
async def get_account_info(vpa: str):
    """
    Get account information from VPA (Virtual Payment Address)
    """
    try:
        # Create mock UPI details with VPA
        upi_details = UPIDetails(pa=vpa)
        account_info = scanner.extract_account_info(upi_details)
        
        if not account_info:
            raise HTTPException(
                status_code=404,
                detail="Could not extract account information from VPA"
            )
        
        return {
            "success": True,
            "vpa": vpa,
            "account_info": account_info
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting account info: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "UPI QR Scanner API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
