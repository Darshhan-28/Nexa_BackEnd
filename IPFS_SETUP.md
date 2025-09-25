# 🚀 NEXA IPFS Integration Guide

This guide will help you set up IPFS (InterPlanetary File System) integration for the NEXA social media platform.

## 📋 Prerequisites

1. **Python 3.7+** installed
2. **IPFS CLI** installed on your system
3. **Internet connection** for IPFS gateway access

## 🔧 Installation Steps

### 1. Install IPFS CLI

#### Windows:
```bash
# Download from https://ipfs.io/docs/install/
# Or use Chocolatey:
choco install ipfs
```

#### macOS:
```bash
# Using Homebrew:
brew install ipfs

# Or download from https://ipfs.io/docs/install/
```

#### Linux:
```bash
# Using package manager:
sudo apt-get install ipfs  # Ubuntu/Debian
sudo yum install ipfs      # CentOS/RHEL

# Or download from https://ipfs.io/docs/install/
```

### 2. Install Python Dependencies

```bash
cd spd/Nexa_app/nexa_app_package/backend
pip install -r requirements.txt
```

### 3. Initialize IPFS (First Time Only)

```bash
# Initialize IPFS repository
ipfs init

# Start IPFS daemon
ipfs daemon
```

## 🧪 Testing IPFS Setup

Run the test script to verify your IPFS installation:

```bash
cd spd/Nexa_app/nexa_app_package/backend
python test_ipfs.py
```

Expected output:
```
🚀 NEXA IPFS Integration Test
========================================
✅ IPFS CLI installed: ipfs version 0.20.0
🔍 Testing IPFS connection...
✅ IPFS daemon connected successfully!
   Version: 0.20.0
   Commit: 1234567
✅ Test file uploaded to IPFS: QmX...
✅ Test file retrieved successfully from IPFS!
✅ IPFS gateway access working: https://ipfs.io/ipfs/QmX...

🎉 All IPFS tests passed! Your setup is ready for NEXA.
```

## 🚀 Running NEXA with IPFS

### 1. Start IPFS Daemon

In a terminal window:
```bash
ipfs daemon
```

### 2. Start NEXA Backend

In another terminal window:
```bash
cd spd/Nexa_app/nexa_app_package/backend
python run_nexa_app.py
```

### 3. Start NEXA Frontend

In a third terminal window:
```bash
cd spd/Nexa_app/nexa_app_package/frontend/project
npm run dev
```

## 🔄 Migration from Local Storage

If you have existing posts with local files, you can migrate them to IPFS:

### Option 1: Using API Endpoint
```bash
curl -X POST http://localhost:5000/api/migrate-to-ipfs
```

### Option 2: Using Python Script
```python
import requests
response = requests.post('http://localhost:5000/api/migrate-to-ipfs')
print(response.json())
```

## 📁 File Storage Locations

### Before IPFS (Local Storage):
- **Posts**: `uploads/` folder
- **Avatars**: `uploads/` folder  
- **Cover Images**: `uploads/` folder
- **Metadata**: JSON files in backend directory

### After IPFS Integration:
- **Posts**: IPFS network (CID-based)
- **Avatars**: IPFS network (CID-based)
- **Cover Images**: IPFS network (CID-based)
- **Metadata**: Still JSON files (local for performance)

## 🔗 IPFS Gateway URLs

Files uploaded to IPFS are accessible via multiple gateways:

- **Primary**: `https://ipfs.io/ipfs/{CID}`
- **Alternative**: `https://gateway.pinata.cloud/ipfs/{CID}`
- **Cloudflare**: `https://cloudflare-ipfs.com/ipfs/{CID}`
- **Local**: `http://localhost:8080/ipfs/{CID}` (if running local gateway)

## 🛠️ Troubleshooting

### IPFS Daemon Not Starting
```bash
# Check if IPFS is already running
ipfs id

# Kill existing daemon
pkill ipfs

# Start fresh
ipfs daemon
```

### Connection Refused
```bash
# Check IPFS API port
ipfs config Addresses.API
# Should show: /ip4/127.0.0.1/tcp/5001

# Check if port is in use
netstat -an | grep 5001
```

### File Upload Fails
1. Ensure IPFS daemon is running
2. Check internet connection
3. Verify IPFS repository is initialized
4. Check available disk space

### Gateway Access Issues
1. Try different gateways
2. Check firewall settings
3. Verify CID is correct
4. Wait a few minutes for IPFS propagation

## 🔒 Security Considerations

1. **Content Addressing**: Files are immutable and content-addressed
2. **Decentralized**: No single point of failure
3. **Permanent**: Files remain accessible as long as someone hosts them
4. **Public**: All IPFS content is publicly accessible

## 📊 Performance Tips

1. **Local Gateway**: Run `ipfs gateway` for faster local access
2. **Caching**: Files are cached locally after first access
3. **Pinning**: Pin important files to keep them available
4. **Bandwidth**: Monitor IPFS bandwidth usage

## 🎯 Features Implemented

✅ **Post Upload**: All posts now upload to IPFS  
✅ **Media Files**: Images and videos stored on IPFS  
✅ **Avatar Upload**: User avatars on IPFS  
✅ **Cover Images**: Profile cover images on IPFS  
✅ **Migration Tool**: Move existing files to IPFS  
✅ **Fallback System**: Local storage if IPFS unavailable  
✅ **Multiple Gateways**: Redundant access points  
✅ **Content Types**: Proper MIME type detection  

## 🚀 Next Steps

1. **Pin Important Content**: Use `ipfs pin add {CID}` for important files
2. **Monitor Storage**: Check IPFS repo size with `ipfs repo stat`
3. **Backup**: Regular backups of metadata files
4. **Optimization**: Consider IPFS cluster for production

---

**Happy decentralized social networking! 🌐**
