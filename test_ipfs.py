#!/usr/bin/env python3
"""
Test script to verify IPFS connectivity and functionality
"""

import ipfshttpclient
import os
import requests

def test_ipfs_connection():
    """Test IPFS daemon connection"""
    try:
        print("🔍 Testing IPFS connection...")
        client = ipfshttpclient.connect()
        
        # Test basic connectivity
        version = client.version()
        print(f"✅ IPFS daemon connected successfully!")
        print(f"   Version: {version.get('Version', 'Unknown')}")
        print(f"   Commit: {version.get('Commit', 'Unknown')}")
        
        # Test adding a simple file
        test_data = b"Hello from NEXA! This is a test file for IPFS integration."
        # Use the correct API for ipfshttpclient 0.8.0
        result = client.add_bytes(test_data)
        # Handle different response formats
        if isinstance(result, dict):
            cid = result.get('Hash', result)
        else:
            cid = str(result)
        print(f"✅ Test file uploaded to IPFS: {cid}")
        
        # Test retrieving the file
        retrieved_data = client.cat(cid)
        if retrieved_data == test_data:
            print(f"✅ Test file retrieved successfully from IPFS!")
        else:
            print(f"❌ Test file retrieval failed - data mismatch")
        
        # Test IPFS gateway access
        gateway_url = f"https://ipfs.io/ipfs/{cid}"
        response = requests.get(gateway_url, timeout=10)
        if response.status_code == 200:
            print(f"✅ IPFS gateway access working: {gateway_url}")
        else:
            print(f"⚠️  IPFS gateway access failed: {response.status_code}")
        
        # Try pinning through local API if backend is running
        try:
            pin_resp = requests.post(f"http://127.0.0.1:5000/api/pin/{cid}", json={"name": "nexa-test"}, timeout=10)
            if pin_resp.status_code == 200:
                print("✅ Pinning via backend succeeded:", pin_resp.json())
            else:
                print("⚠️  Pinning via backend failed:", pin_resp.status_code, pin_resp.text[:200])
        except Exception as e:
            print("ℹ️  Skipping backend pin test (server may not be running):", e)
        
        return True
        
    except Exception as e:
        print(f"❌ IPFS connection failed: {e}")
        print("\n🔧 Troubleshooting tips:")
        print("1. Make sure IPFS daemon is running: ipfs daemon")
        print("2. Check if IPFS is installed: ipfs --version")
        print("3. Verify the daemon is accessible on default port 5001")
        return False

def test_ipfs_installation():
    """Test if IPFS is properly installed"""
    try:
        import subprocess
        result = subprocess.run(['ipfs', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ IPFS CLI installed: {result.stdout.strip()}")
            return True
        else:
            print("❌ IPFS CLI not found")
            return False
    except FileNotFoundError:
        print("❌ IPFS CLI not found in PATH")
        return False

if __name__ == "__main__":
    print("🚀 NEXA IPFS Integration Test")
    print("=" * 40)
    
    # Test IPFS installation
    if test_ipfs_installation():
        # Test IPFS connection
        if test_ipfs_connection():
            print("\n🎉 All IPFS tests passed! Your setup is ready for NEXA.")
        else:
            print("\n❌ IPFS connection failed. Please check your IPFS daemon.")
    else:
        print("\n❌ IPFS not installed. Please install IPFS first.")
        print("   Download from: https://ipfs.io/docs/install/")
