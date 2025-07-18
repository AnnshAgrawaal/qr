#!/usr/bin/env python3
"""
Test script to verify UPI QR Scanner setup
Run this script to check if all dependencies are properly installed
"""

import sys
import importlib

def test_import(module_name, package_name=None):
    """Test if a module can be imported"""
    try:
        importlib.import_module(module_name)
        print(f"✅ {package_name or module_name} - OK")
        return True
    except ImportError as e:
        print(f"❌ {package_name or module_name} - FAILED: {e}")
        return False

def test_python_version():
    """Check Python version"""
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} - OK")
        return True
    else:
        print(f"❌ Python {version.major}.{version.minor}.{version.micro} - Need Python 3.8+")
        return False

def test_opencv():
    """Test OpenCV specifically"""
    try:
        import cv2
        print(f"✅ OpenCV {cv2.__version__} - OK")
        return True
    except ImportError as e:
        print(f"❌ OpenCV - FAILED: {e}")
        return False

def test_pyzbar():
    """Test pyzbar specifically"""
    try:
        import pyzbar
        from pyzbar import pyzbar as pyzbar_module
        print(f"✅ pyzbar - OK")
        return True
    except ImportError as e:
        print(f"❌ pyzbar - FAILED: {e}")
        print("💡 Try installing system dependencies:")
        print("   Ubuntu/Debian: sudo apt-get install libzbar0 libzbar-dev")
        print("   macOS: brew install zbar")
        print("   CentOS/RHEL: sudo yum install zbar-devel")
        return False

def main():
    """Main test function"""
    print("🔍 Testing UPI QR Scanner Setup...")
    print("=" * 50)
    
    tests = [
        ("Python Version", test_python_version),
        ("FastAPI", lambda: test_import("fastapi")),
        ("Uvicorn", lambda: test_import("uvicorn")),
        ("Pydantic", lambda: test_import("pydantic")),
        ("NumPy", lambda: test_import("numpy")),
        ("Pillow", lambda: test_import("PIL", "Pillow")),
        ("OpenCV", test_opencv),
        ("pyzbar", test_pyzbar),
        ("Python Multipart", lambda: test_import("multipart", "python-multipart")),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        if test_func():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your setup is ready.")
        print("🚀 You can now run: python main.py")
    else:
        print("⚠️  Some tests failed. Please install missing dependencies.")
        print("📖 Check the setup guide for installation instructions.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)