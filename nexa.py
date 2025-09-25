import os
from werkzeug.utils import secure_filename
from flask import send_from_directory, redirect
from flask import Flask, request, jsonify, make_response, Response
from flask_cors import CORS
import uuid
import jwt
import datetime
import requests
import json
import os
import hashlib
import secrets
from collections import defaultdict
import time
try:
    import bcrypt
except ImportError:
    bcrypt = None
try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None

# Initialize Flask app
app = Flask(__name__)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "mp4", "mov", "avi", "mkv", "webm"}
# Configuration
MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1GB
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE
# Use a strong default secret if env is not set
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", secrets.token_urlsafe(64))

# IPFS Configuration
IPFS_API_URL = "http://127.0.0.1:5001"

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def is_image_file(filename):
    image_extensions = {"png", "jpg", "jpeg", "gif", "webp"}
    return "." in filename and filename.rsplit(".", 1)[1].lower() in image_extensions

def is_video_file(filename):
    video_extensions = {"mp4", "mov", "avi", "mkv", "webm"}
    return "." in filename and filename.rsplit(".", 1)[1].lower() in video_extensions

# Tighten CORS: adjust origins as needed
CORS(app, resources={r"/api/*": {"origins": [
    "http://localhost:5173",
    "http://127.0.0.1:5173"
]}})

@app.after_request
def add_security_headers(response):
    try:
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "img-src 'self' data: https://ipfs.io https://*.ipfs.* https://cloudflare-ipfs.com https://gateway.pinata.cloud; "
            "media-src 'self' https://ipfs.io https://*.ipfs.* https://cloudflare-ipfs.com https://gateway.pinata.cloud; "
            "connect-src 'self' http://127.0.0.1:5000 https://ipfs.io https://*.ipfs.* https://cloudflare-ipfs.com https://gateway.pinata.cloud; "
            "script-src 'self'; style-src 'self' 'unsafe-inline'" )
    except Exception:
        pass
    return response

# Persistent storage files
USERS_METADATA_FILE = "users_metadata.json"
POSTS_METADATA_FILE = "posts_metadata.json"

FOLLOWERS_METADATA_FILE = "followers_metadata.json"
FOLLOWING_METADATA_FILE = "following_metadata.json"
SHARES_METADATA_FILE = "shares_metadata.json"
SETTINGS_METADATA_FILE = "settings_metadata.json"
NOTIFICATIONS_METADATA_FILE = "notifications_metadata.json"

# ===== Core Utility Functions =====
KEY_FILE = "nexa_encryption.key"

def _load_encryption_key():
    if not Fernet:
        return None
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, "rb") as f:
                return f.read()
        except Exception:
            return None
    try:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        try:
            os.chmod(KEY_FILE, 0o600)
        except Exception:
            pass
        return key
    except Exception:
        return None

_FERNET = Fernet(_load_encryption_key()) if Fernet else None
def load_metadata(file_path, default_factory=dict):
    try:
        if os.path.exists(file_path):
            # Try encrypted first
            try:
                with open(file_path, "rb") as f:
                    raw = f.read()
                if _FERNET:
                    try:
                        decrypted = _FERNET.decrypt(raw)
                        data = json.loads(decrypted.decode())
                    except Exception:
                        # Fallback: treat as plaintext JSON
                        data = json.loads(raw.decode(errors='ignore'))
                else:
                    data = json.loads(raw.decode(errors='ignore'))
            except Exception:
                # Last resort: plaintext read
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
            if isinstance(data, list):
                return {item['id']: item for item in data} if file_path == POSTS_METADATA_FILE else data
            return data
        return default_factory()
    except Exception:
        return default_factory()

def save_metadata(file_path, data):
    # Convert sets to lists for JSON serialization
    def convert_sets(obj):
        if isinstance(obj, dict):
            return {k: convert_sets(v) for k, v in obj.items()}
        elif isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, list):
            return [convert_sets(i) for i in obj]
        else:
            return obj

    data_to_save = convert_sets(data)

    try:
        payload = json.dumps(data_to_save, ensure_ascii=False, separators=(",", ":")).encode()
        if _FERNET:
            try:
                payload = _FERNET.encrypt(payload)
            except Exception:
                pass
        # Write bytes (encrypted or plaintext json)
        with open(file_path, "wb") as f:
            f.write(payload)
        try:
            os.chmod(file_path, 0o600)
        except Exception:
            pass
    except Exception:
        # Fallback to plaintext json write
        with open(file_path, "w", encoding="utf-8") as f:
            if isinstance(data_to_save, dict):
                json.dump(data_to_save, f, indent=2)
            else:
                json.dump(list(data_to_save), f, indent=2)

def generate_did():
    return f"did:nexa:{uuid.uuid4()}"

ACCESS_TOKEN_TTL_HOURS = 1

def generate_jwt(did):
    payload = {
        "did": did,
        "type": "access",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=ACCESS_TOKEN_TTL_HOURS)
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

REFRESH_TOKEN_TTL_DAYS = 7

def generate_refresh_jwt(did):
    payload = {
        "did": did,
        "type": "refresh",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=REFRESH_TOKEN_TTL_DAYS)
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

def decode_jwt(token):
    try:
        return jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def hash_password(password):
    if bcrypt:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode()
    # Fallback to legacy (not recommended)
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(password, hashed_value):
    try:
        if bcrypt and isinstance(hashed_value, str) and hashed_value.startswith("$2b$"):
            return bcrypt.checkpw(password.encode('utf-8'), hashed_value.encode('utf-8'))
    except Exception:
        pass
    # Legacy sha256 comparison
    try:
        return hashlib.sha256(password.encode('utf-8')).hexdigest() == hashed_value
    except Exception:
        return False

# Simple in-memory rate limiting for login
_LOGIN_ATTEMPTS = defaultdict(list)
_LOGIN_WINDOW_SECONDS = 300
_LOGIN_MAX_ATTEMPTS = 5

def _is_rate_limited(identifier):
    now = time.time()
    recent = [t for t in _LOGIN_ATTEMPTS[identifier] if now - t < _LOGIN_WINDOW_SECONDS]
    _LOGIN_ATTEMPTS[identifier] = recent
    return len(recent) >= _LOGIN_MAX_ATTEMPTS

def _record_failed_attempt(identifier):
    _LOGIN_ATTEMPTS[identifier].append(time.time())

def upload_to_ipfs(data, filename="file"):
    """Upload file directly to IPFS. Returns CID on success, None on failure."""
    try:
        import ipfshttpclient
        # Connect to local IPFS daemon
        client = ipfshttpclient.connect()
        
        # Add the file to IPFS - use correct API for version 0.8.0
        result = client.add_bytes(data)
        
        # Handle different response formats
        if isinstance(result, dict):
            cid = result.get('Hash', result)
        else:
            cid = str(result)
        
        print(f"✅ File uploaded to IPFS: {cid}")
        print(f"🌐 IPFS Gateway URL: https://ipfs.io/ipfs/{cid}")
        
        return cid
    except ImportError:
        print("❌ ipfshttpclient not installed - IPFS upload failed")
        return None
    except Exception as e:
        print(f"❌ IPFS upload error: {e}")
        return None







def download_from_ipfs(cid):
    """Download file from IPFS using CID"""
    try:
        import ipfshttpclient
        # Connect to local IPFS daemon
        client = ipfshttpclient.connect()
        
        # Get the file from IPFS
        data = client.cat(cid)
        print(f"File downloaded from IPFS: {cid}")
        return data
    except ImportError:
        print("ipfshttpclient not installed, trying HTTP gateway")
        return download_from_ipfs_gateway(cid)
    except Exception as e:
        print(f"IPFS download error: {e}")
        print("Trying HTTP gateway as fallback")
        return download_from_ipfs_gateway(cid)

def download_from_ipfs_gateway(cid):
    """Download file from IPFS using HTTP gateway as fallback"""
    try:
        # Try multiple IPFS gateways
        gateways = [
            f"https://ipfs.io/ipfs/{cid}",
            f"https://gateway.pinata.cloud/ipfs/{cid}",
            f"https://cloudflare-ipfs.com/ipfs/{cid}",
            f"https://dweb.link/ipfs/{cid}"
        ]
        
        for gateway_url in gateways:
            try:
                res = requests.get(gateway_url, timeout=10)
                if res.status_code == 200:
                    print(f"File downloaded from gateway: {gateway_url}")
                    return res.content
            except Exception as e:
                print(f"Gateway {gateway_url} failed: {e}")
                continue
        
        print("All IPFS gateways failed")
        return None
    except Exception as e:
        print(f"IPFS gateway download error: {e}")
        return None

@app.route("/api/pin/<cid>", methods=["POST"])
def pin_cid(cid):
    """Pin a CID to ensure availability. Pins on local node and optionally Pinata if configured."""
    try:
        label = (request.get_json(silent=True) or {}).get("name")
        result = {"cid": cid, "local": None, "pinata": None}

        # Local pin
        try:
            import ipfshttpclient
            client = ipfshttpclient.connect()
            client.pin.add(cid)
            result["local"] = {"pinned": True}
        except Exception as e:
            print(f"Local pin failed for {cid}: {e}")
            result["local"] = {"pinned": False, "error": str(e)}

        # Pinata pin (optional)
        pinata_jwt = os.getenv("PINATA_JWT")
        pinata_key = os.getenv("PINATA_API_KEY")
        pinata_secret = os.getenv("PINATA_API_SECRET")
        try:
            if pinata_jwt or (pinata_key and pinata_secret):
                url = "https://api.pinata.cloud/pinning/pinByHash"
                headers = {"Content-Type": "application/json"}
                if pinata_jwt:
                    headers["Authorization"] = f"Bearer {pinata_jwt}"
                else:
                    headers["pinata_api_key"] = pinata_key
                    headers["pinata_secret_api_key"] = pinata_secret
                payload = {"hashToPin": cid}
                if label:
                    payload["pinataMetadata"] = {"name": label}
                r = requests.post(url, json=payload, headers=headers, timeout=15)
                if r.status_code in (200, 202):
                    result["pinata"] = {"pinned": True, "status": r.status_code}
                else:
                    result["pinata"] = {"pinned": False, "status": r.status_code, "error": r.text[:200]}
            else:
                result["pinata"] = {"pinned": False, "skipped": True, "reason": "PINATA_JWT or API keys not configured"}
        except Exception as e:
            print(f"Pinata pin failed for {cid}: {e}")
            result["pinata"] = {"pinned": False, "error": str(e)}

        if result["local"].get("pinned") or result["pinata"].get("pinned"):
            return jsonify({"message": "Pinned", **result}), 200
        return jsonify({"error": "Pin failed", **result}), 500

    except Exception as e:
        print(f"Error in pin_cid: {e}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

def migrate_local_files_to_ipfs():
    """Migrate existing local files to IPFS"""
    try:
        import ipfshttpclient
        client = ipfshttpclient.connect()
        
        migrated_count = 0
        failed_count = 0
        
        # Migrate posts with local file URLs
        for post_id, post in posts.items():
            if post.get('file_url') and post['file_url'].startswith('/uploads/'):
                try:
                    # Extract filename from URL
                    filename = post['file_url'].replace('/uploads/', '')
                    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                    
                    if os.path.exists(file_path):
                        # Read file and upload to IPFS
                        with open(file_path, 'rb') as f:
                            file_data = f.read()
                        
                        # Upload to IPFS
                        result = client.add_bytes(file_data)
                        # Handle different response formats
                        if isinstance(result, dict):
                            cid = result.get('Hash', result)
                        else:
                            cid = str(result)
                        
                        # Update post with IPFS URL
                        post['cid'] = cid
                        post['file_url'] = f"https://ipfs.io/ipfs/{cid}"
                        post['preview'] = f"https://ipfs.io/ipfs/{cid}"
                        
                        migrated_count += 1
                        print(f"Migrated post {post_id} to IPFS: {cid}")
                        
                except Exception as e:
                    print(f"Failed to migrate post {post_id}: {e}")
                    failed_count += 1
        
        # Migrate user avatars and cover images
        for did, user in users.items():
            # Migrate avatar
            if user.get('avatar') and user['avatar'].startswith('/uploads/'):
                try:
                    filename = user['avatar'].replace('/uploads/', '')
                    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                    
                    if os.path.exists(file_path):
                        with open(file_path, 'rb') as f:
                            file_data = f.read()
                        
                        result = client.add_bytes(file_data)
                        # Handle different response formats
                        if isinstance(result, dict):
                            cid = result.get('Hash', result)
                        else:
                            cid = str(result)
                        
                        user['avatar'] = f"https://ipfs.io/ipfs/{cid}"
                        migrated_count += 1
                        print(f"Migrated avatar for user {did} to IPFS: {cid}")
                        
                except Exception as e:
                    print(f"Failed to migrate avatar for user {did}: {e}")
                    failed_count += 1
            
            # Migrate cover image
            if user.get('cover_image') and user['cover_image'].startswith('/uploads/'):
                try:
                    filename = user['cover_image'].replace('/uploads/', '')
                    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                    
                    if os.path.exists(file_path):
                        with open(file_path, 'rb') as f:
                            file_data = f.read()
                        
                        result = client.add_bytes(file_data)
                        # Handle different response formats
                        if isinstance(result, dict):
                            cid = result.get('Hash', result)
                        else:
                            cid = str(result)
                        
                        user['cover_image'] = f"https://ipfs.io/ipfs/{cid}"
                        migrated_count += 1
                        print(f"Migrated cover image for user {did} to IPFS: {cid}")
                        
                except Exception as e:
                    print(f"Failed to migrate cover image for user {did}: {e}")
                    failed_count += 1
        
        # Save updated metadata
        save_metadata(POSTS_METADATA_FILE, posts)
        save_metadata(USERS_METADATA_FILE, users)
        
        print(f"Migration completed: {migrated_count} files migrated, {failed_count} failed")
        return {"migrated": migrated_count, "failed": failed_count}
        
    except ImportError:
        print("ipfshttpclient not installed, cannot migrate to IPFS")
        return {"error": "IPFS client not available"}
    except Exception as e:
        print(f"Migration error: {e}")
        return {"error": str(e)}

def delete_all_hidden_posts():
    """Delete all posts marked as hidden from the system"""
    try:
        deleted_count = 0
        posts_to_delete = []
        
        # Find all hidden posts
        for post_id, post_data in posts.items():
            if post_data.get('hidden', False):
                posts_to_delete.append(post_id)
        
        # Delete each hidden post
        for post_id in posts_to_delete:
            post_data = posts[post_id]
            
            # Remove from posts metadata
            del posts[post_id]
            deleted_count += 1
            print(f"Deleted hidden post: {post_id}")
        
        # Save updated metadata
        save_metadata(POSTS_METADATA_FILE, posts)
        
        return {
            'success': True,
            'message': f'Successfully deleted {deleted_count} hidden posts',
            'deleted_count': deleted_count
        }
        
    except Exception as e:
        print(f"Error deleting hidden posts: {e}")
        return {
            'success': False,
            'message': f'Error deleting hidden posts: {str(e)}',
            'deleted_count': 0
        }

# ===== Data Initialization =====
users = load_metadata(USERS_METADATA_FILE)
posts = load_metadata(POSTS_METADATA_FILE)

followers = load_metadata(FOLLOWERS_METADATA_FILE, lambda: {})
following = load_metadata(FOLLOWING_METADATA_FILE, lambda: {})
shares_metadata = load_metadata(SHARES_METADATA_FILE, lambda: {})
settings_metadata = load_metadata(SETTINGS_METADATA_FILE, lambda: {})
notifications_metadata = load_metadata(NOTIFICATIONS_METADATA_FILE, lambda: {})

# Initialize default values for new users
for did in users:
    followers.setdefault(did, set())
    following.setdefault(did, set())
    shares_metadata.setdefault(did, [])
    notifications_metadata.setdefault(did, [])
    # Initialize default settings for users
    if did not in settings_metadata:
        settings_metadata[did] = {
            "theme": "dark",
            "font_size": "medium",
            "notifications": {
                "push_notifications": True,
                "new_followers": True,
                "mentions": True,
                "likes": True,
                "comments": True,
                "shares": True
            },
            "privacy": {
                "profile_visibility": "public",
                "show_online_status": True,
                "allow_messages": True
            },
            "language": "en"
        }

# Normalize followers/following structures loaded from JSON to use sets in-memory
def _normalize_relationship_sets():
    try:
        # Followers
        keys = list(followers.keys()) if isinstance(followers, dict) else []
        for did in keys:
            value = followers.get(did, set())
            if isinstance(value, list):
                followers[did] = set(value)
            elif not isinstance(value, set):
                try:
                    followers[did] = set(value)
                except Exception:
                    followers[did] = set()

        # Following
        keys = list(following.keys()) if isinstance(following, dict) else []
        for did in keys:
            value = following.get(did, set())
            if isinstance(value, list):
                following[did] = set(value)
            elif not isinstance(value, set):
                try:
                    following[did] = set(value)
                except Exception:
                    following[did] = set()
    except Exception as e:
        print(f"Error normalizing relationship sets: {e}")

_normalize_relationship_sets()

# ===== Serialization Helpers =====
def enrich_post_with_current_user_fields(post_obj, current_user_did=None):
    """Return a shallow copy of post with up-to-date user fields (avatar/display_name/username).
    Does not mutate stored data, only the response payload.
    Also enriches nested original_post if present.
    """
    try:
        if not isinstance(post_obj, dict):
            return post_obj
        post_copy = dict(post_obj)
        author_did = post_copy.get('did')
        if author_did and author_did in users:
            user_rec = users[author_did]
            post_copy['username'] = user_rec.get('username', post_copy.get('username', ''))
            post_copy['display_name'] = user_rec.get('display_name', user_rec.get('username', post_copy.get('display_name', '')))
            post_copy['avatar'] = user_rec.get('avatar', post_copy.get('avatar', ''))
        
        # Set isLiked field if current user is provided
        if current_user_did:
            liked_by = post_copy.get('liked_by', [])
            post_copy['isLiked'] = current_user_did in liked_by

        # Enrich embedded original post (for reposts) if we can resolve it
        original = post_copy.get('original_post')
        if isinstance(original, dict):
            orig_id = original.get('id')
            if orig_id and orig_id in posts:
                resolved = posts[orig_id]
                resolved_copy = dict(original)
                orig_did = resolved.get('did')
                if orig_did and orig_did in users:
                    orig_user = users[orig_did]
                    resolved_copy['username'] = orig_user.get('username', resolved.get('username', original.get('username', '')))
                    resolved_copy['display_name'] = orig_user.get('display_name', orig_user.get('username', resolved.get('display_name', original.get('display_name', ''))))
                    resolved_copy['avatar'] = orig_user.get('avatar', original.get('avatar', ''))
                # prefer latest preview/file_info if present
                if 'preview' in resolved:
                    resolved_copy['preview'] = resolved.get('preview')
                if 'file_info' in resolved:
                    resolved_copy['file_info'] = resolved.get('file_info')
                post_copy['original_post'] = resolved_copy
        return post_copy
    except Exception as e:
        print(f"enrich_post_with_current_user_fields error: {e}")
        return post_obj


# ===== API Routes =====
@app.route("/")
def home():
    return jsonify({
        "message": "Nexa API Server is running",
        "endpoints": {
            "auth": ["/api/register", "/api/login"],
            "posts": ["/api/post", "/api/posts", "/api/reply/<parent_id>"],
            "social": ["/api/follow/<target_did>", "/api/followers/<did>", "/api/following/<did>"],
            "shares": ["/api/share/<post_id>", "/api/shares/<did>", "/api/shares/post/<post_id>"],
            "ai": ["/api/ai/chat", "/api/ai/history", "/api/ai/clear"],
            "storage": ["/api/migrate-to-ipfs"]
        }
    })

# ==== Auth & User Routes ====
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    if any(user['username'] == username for user in users.values()):
        return jsonify({"error": "Username already exists"}), 400

    hashed_password = hash_password(password)
    did = generate_did()
    users[did] = {
        "username": username,
        "password": hashed_password,
        "bio": "",
        "avatar": "",
        "cover_image": "",
        "display_name": username,
        "location": "",
        "website": "",
        "created_at": datetime.datetime.now().isoformat()
    }
    followers[did] = set()
    following[did] = set()
    shares_metadata[did] = []
    notifications_metadata[did] = []
    
    save_metadata(USERS_METADATA_FILE, users)
    save_metadata(FOLLOWERS_METADATA_FILE, followers)
    save_metadata(FOLLOWING_METADATA_FILE, following)
    save_metadata(SHARES_METADATA_FILE, shares_metadata)
    save_metadata(NOTIFICATIONS_METADATA_FILE, notifications_metadata)
    
    token = generate_jwt(did)
    refresh = generate_refresh_jwt(did)
    return jsonify({
        "did": did,
        "token": token,
        "refresh_token": refresh,
        "username": username
    })

@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        print("Login data received:", data)
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        identifier = f"{request.remote_addr}:{username}"
        if _is_rate_limited(identifier):
            return jsonify({"error": "Too many attempts. Try again later."}), 429

        user = next((u for u in users.values() if u["username"] == username), None)
        if user and verify_password(password, user.get("password", "")):
            did = next(did for did, u in users.items() if u == user)
            # If legacy sha256 detected, upgrade to bcrypt hash
            if bcrypt and not str(user.get("password", "")).startswith("$2b$"):
                try:
                    users[did]["password"] = hash_password(password)
                    save_metadata(USERS_METADATA_FILE, users)
                except Exception:
                    pass
            token = generate_jwt(did)
            refresh = generate_refresh_jwt(did)
            print("Login successful for user:", username)
            return jsonify({
                "token": token,
                "refresh_token": refresh,
                "did": did,
                "username": username
            })
        else:
            print("Invalid username or password for user:", username)
            _record_failed_attempt(identifier)
            return jsonify({"error": "Invalid username or password"}), 401
    except Exception as e:
        print("Exception during login:", e)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/token/refresh", methods=["POST"])
def refresh_token():
    try:
        data = request.get_json() or {}
        token = data.get("refresh_token") or request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "Missing refresh token"}), 400
        payload = decode_jwt(token)
        if not payload or payload.get("type") != "refresh":
            return jsonify({"error": "Invalid or expired token"}), 403
        new_access = generate_jwt(payload["did"])
        return jsonify({"token": new_access})
    except Exception as e:
        print("Exception during refresh:", e)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/profile/<did>", methods=["GET", "POST"])
def profile(did):
    if request.method == "GET":
        user = users.get(did)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({
            "username": user["username"],
            "bio": user.get("bio", ""),
            "avatar": user.get("avatar", ""),
            "cover_image": user.get("cover_image", ""),
            "display_name": user.get("display_name", user["username"]),
            "location": user.get("location", ""),
            "website": user.get("website", ""),
            "created_at": user.get("created_at"),
            "followers_count": len(followers.get(did, [])),
            "following_count": len(following.get(did, [])),
            "posts_count": len([p for p in posts.values() if p["did"] == did and not p.get("hidden", False)]),
            "shares_count": len([s for s in shares_metadata.get(did, [])]),
            "pinned_post_id": user.get("pinned_post_id")
        })

    elif request.method == "POST":
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        payload = decode_jwt(token)
        if not payload or payload["did"] != did:
            return jsonify({"error": "Unauthorized"}), 403

        data = request.get_json()
        
        # Update profile fields
        if "bio" in data:
            users[did]["bio"] = data["bio"]
        if "display_name" in data:
            users[did]["display_name"] = data["display_name"]
        if "location" in data:
            users[did]["location"] = data["location"]
        if "website" in data:
            users[did]["website"] = data["website"]
        
        save_metadata(USERS_METADATA_FILE, users)
        return jsonify({
            "message": "Profile updated successfully",
            "user": {
                "bio": users[did].get("bio", ""),
                "display_name": users[did].get("display_name", ""),
                "location": users[did].get("location", ""),
                "website": users[did].get("website", "")
            }
        })

# ==== Posts Routes ====
@app.route("/api/post", methods=["POST"])
def create_post():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        try:
            token = (
                request.form.get("token")
                or request.args.get("token")
                or (request.get_json(silent=True) or {}).get("token", "")
                or request.headers.get("X-Auth-Token", "")
            )
        except Exception:
            token = ""
    payload = decode_jwt(token)
    if not payload:
        # Compatibility fallback: accept explicit DID
        fallback_did = (
            request.form.get("did")
            or request.args.get("did")
            or (request.get_json(silent=True) or {}).get("did")
        )
        if fallback_did and fallback_did in users:
            payload = {"did": fallback_did}
        else:
            return jsonify({"error": "Invalid or expired token"}), 403

    did = payload["did"]
    content = request.form.get("content", "")
    parent_id = request.form.get("parent_id")
    file = request.files.get("file")

    # Allow posts with just files (no content required)
    if not content and not file:
        return jsonify({"error": "Content or file required"}), 400

    # Handle file upload
    file_data = None
    file_info = None
    
    if file:
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
            
        if not allowed_file(file.filename):
            return jsonify({"error": "Invalid file type. Allowed: PNG, JPG, JPEG, GIF, WebP, MP4, MOV, AVI, MKV, WebM"}), 400
        
        # Check file size
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({"error": f"File too large. Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB"}), 400
        
        # Read file data
        file_data = file.read()
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        
        # Determine file type
        if is_image_file(file.filename):
            file_type = "image"
        elif is_video_file(file.filename):
            file_type = "video"
        else:
            file_type = "file"
        
        file_info = {
            "filename": secure_filename(file.filename),
            "type": file_type,
            "extension": file_extension,
            "size": file_size
        }

    # Prepare data to upload
    upload_data = file_data if file_data else content.encode()
    filename = f"post_{datetime.datetime.now().timestamp()}"
    if file_info:
        filename += f".{file_info['extension']}"

        # Upload directly to IPFS - no local storage
    cid = upload_to_ipfs(upload_data, filename=filename)
    if not cid:
        return jsonify({"error": "IPFS upload failed. Please ensure IPFS is running and try again."}), 500
    
    # IPFS upload successful
    preview_url = f"https://ipfs.io/ipfs/{cid}"
    cid_value = str(cid)
    print(f"✅ File uploaded directly to IPFS: {cid}")

    post_id = str(uuid.uuid4())
    post = {
        "id": post_id,
        "did": did,
        "username": users[did]["username"],
        "display_name": users[did].get("display_name", users[did]["username"]),
        "avatar": users[did].get("avatar", ""),
        "content": content,
        "cid": cid_value,
        "preview": preview_url,
        "file_url": preview_url if file_info else None,
        "file_type": file_info["type"] if file_info else None,
        "timestamp": datetime.datetime.now().isoformat(),
        "likes": 0,
        "parent_id": parent_id,
        "replies_count": 0,
        "file_info": file_info,
        "shares_count": 0,
        "liked_by": [],
        "hidden": False
    }
    
    if parent_id and parent_id in posts:
        posts[parent_id]["replies_count"] = posts[parent_id].get("replies_count", 0) + 1
    
    posts[post_id] = post
    save_metadata(POSTS_METADATA_FILE, posts)


    
    return jsonify({
        "message": "Post created",
        "post": post
    })

@app.route("/api/upload-avatar", methods=["POST"])
def upload_avatar():
    """Upload and update user avatar with JWT validation."""
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        payload = decode_jwt(token)
        
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 403
        
        if 'avatar' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['avatar']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Validate file type
        if not is_image_file(file.filename):
            return jsonify({"error": "Invalid file type. Only PNG, JPG, JPEG, GIF, and WebP are allowed"}), 400
        
        # Validate file size (max 10MB for avatar)
        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > 10 * 1024 * 1024:  # 10MB
            return jsonify({"error": "File size too large. Maximum 10MB allowed"}), 400
        
        # Generate unique filename based on user DID
        user_did = payload["did"]
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        # Sanitize the DID for Windows compatibility (remove colons and other invalid characters)
        safe_did = user_did.replace(':', '_').replace('/', '_').replace('\\', '_')
        filename = f"{safe_did}_avatar.{file_extension}"
        
        # Read file data
        file_data = file.read()
        
        # Upload to IPFS
        cid = upload_to_ipfs(file_data, filename=filename)
        if not cid:
            return jsonify({"error": "File upload failed"}), 500
        
        # Update user avatar in database
        if user_did in users:
            # IPFS storage only
            avatar_url = f"https://ipfs.io/ipfs/{cid}"
            
            users[user_did]["avatar"] = avatar_url
            save_metadata(USERS_METADATA_FILE, users)
            
            return jsonify({
                "success": True,
                "url": avatar_url,
                "cid": cid,
                "message": "Avatar updated successfully"
            })
        
        return jsonify({"error": "User not found"}), 404
        
    except Exception as e:
        print(f"Error in upload_avatar: {str(e)}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/api/upload-cover", methods=["POST"])
def upload_cover():
    """Upload and update user cover image with JWT validation."""
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        payload = decode_jwt(token)
        
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 403
        
        if 'cover' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['cover']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Validate file type
        if not is_image_file(file.filename):
            return jsonify({"error": "Invalid file type. Only PNG, JPG, JPEG, GIF, and WebP are allowed"}), 400
        
        # Validate file size (max 20MB for cover image)
        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > 20 * 1024 * 1024:  # 20MB
            return jsonify({"error": "File size too large. Maximum 20MB allowed"}), 400
        
        # Generate unique filename based on user DID
        user_did = payload["did"]
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        # Sanitize the DID for Windows compatibility (remove colons and other invalid characters)
        safe_did = user_did.replace(':', '_').replace('/', '_').replace('\\', '_')
        filename = f"{safe_did}_cover.{file_extension}"
        
        # Read file data
        file_data = file.read()
        
        # Upload to IPFS
        cid = upload_to_ipfs(file_data, filename=filename)
        if not cid:
            return jsonify({"error": "File upload failed"}), 500
        
        # Update user cover image in database
        if user_did in users:
            # IPFS storage only
            cover_url = f"https://ipfs.io/ipfs/{cid}"
            
            users[user_did]["cover_image"] = cover_url
            save_metadata(USERS_METADATA_FILE, users)
            
            return jsonify({
                "success": True,
                "url": cover_url,
                "cid": cid,
                "message": "Cover image updated successfully"
            })
        
        return jsonify({"error": "User not found"}), 404
        
    except Exception as e:
        print(f"Error in upload_cover: {str(e)}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    """Serve uploaded files - Redirects to IPFS gateway"""
    # This route should not be used anymore since files are on IPFS
    # Return a helpful message
    return jsonify({
        "error": "File not found locally",
        "message": "Files are now stored on IPFS, not locally",
        "note": "Check the post's 'preview' or 'file_url' field for the IPFS gateway URL"
    }), 404

@app.route("/api/ipfs/<cid>")
def serve_ipfs_file(cid):
    """Stream an IPFS file via backend with Range support and multi-gateway fallback."""
    try:
        range_header = request.headers.get('Range')

        # Gateways to try in order (prefer local gateway if daemon is running)
        gateways = [
            f"http://127.0.0.1:8080/ipfs/{cid}",
            f"https://ipfs.io/ipfs/{cid}",
            f"https://cloudflare-ipfs.com/ipfs/{cid}",
            f"https://dweb.link/ipfs/{cid}",
            f"https://nftstorage.link/ipfs/{cid}",
            f"https://ipfs.filebase.io/ipfs/{cid}",
            f"https://gateway.pinata.cloud/ipfs/{cid}",
        ]

        headers = {}
        if range_header:
            headers['Range'] = range_header

        # Shared HTTP session with retries
        session = requests.Session()
        try:
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retry)
            session.mount('http://', adapter)
            session.mount('https://', adapter)
        except Exception:
            pass

        # Try streaming from local node first if available
        try:
            import ipfshttpclient
            client = ipfshttpclient.connect()
            # If Range not requested, stream whole file
            if not range_header:
                data = client.cat(cid)
                return Response(data, status=200, headers={
                    'Content-Type': 'application/octet-stream',
                    'Accept-Ranges': 'bytes',
                    'Cache-Control': 'public, max-age=31536000, immutable'
                })
        except Exception:
            pass

        # Fallback to HTTP gateways: probe with HEAD, then stream GET
        for url in gateways:
            try:
                # Probe with HEAD to validate availability and get headers
                head = session.head(url, headers={**headers, 'Connection': 'keep-alive'}, timeout=8, allow_redirects=True)
                if head.status_code not in (200, 206):
                    continue
                # Stream GET after successful HEAD
                r = session.get(url, headers={**headers, 'Connection': 'keep-alive'}, stream=True, timeout=(8, 60))
                if r.status_code in (200, 206):
                    # Build response with relevant headers
                    resp_headers = {}
                    ct = r.headers.get('Content-Type')
                    if ct:
                        resp_headers['Content-Type'] = ct
                    cl = r.headers.get('Content-Length')
                    if cl:
                        resp_headers['Content-Length'] = cl
                    cr = r.headers.get('Content-Range')
                    if cr:
                        resp_headers['Content-Range'] = cr
                    if r.headers.get('Accept-Ranges'):
                        resp_headers['Accept-Ranges'] = r.headers['Accept-Ranges']
                    resp_headers['Cache-Control'] = 'public, max-age=31536000, immutable'

                    def generate():
                        try:
                            for chunk in r.iter_content(chunk_size=65536):
                                if chunk:
                                    yield chunk
                        except Exception as e:
                            # End stream silently on read timeouts/disconnects
                            print(f"Stream error for {url}: {e}")
                            return

                    return Response(generate(), status=r.status_code, headers=resp_headers)
            except Exception as e:
                print(f"Gateway stream failed {url}: {e}")
                continue

        return jsonify({"error": "IPFS fetch failed", "cid": cid}), 502
    except Exception as e:
        print(f"Error streaming IPFS {cid}: {e}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


@app.route("/api/posts", methods=["GET"])
def get_posts():
    # Get pagination parameters
    page = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 20)), 50)  # Max 50 posts per request
    offset = (page - 1) * limit
    
    # Filter out comments (posts with parent_id) and hidden posts from main posts list
    main_posts = [post for post in posts.values() if not post.get("parent_id") and not post.get("hidden", False)]
    total_posts = len(main_posts)
    
    # Sort by timestamp (newest first)
    sorted_posts = sorted(main_posts, key=lambda x: x["timestamp"], reverse=True)
    
    # Apply pagination
    paginated_posts = sorted_posts[offset:offset + limit]
    
    # Enrich posts (this is expensive, so only do it for the current page)
    # Note: We can't enrich with user-specific fields here since we don't have the current user
    enriched = [enrich_post_with_current_user_fields(p) for p in paginated_posts]
    
    return jsonify({
        "posts": enriched,
        "total": total_posts,
        "page": page,
        "limit": limit,
        "has_more": offset + limit < total_posts
    })

@app.route("/api/user/<did>/posts", methods=["GET"])
def get_user_posts(did):
    """Get all posts by a specific user"""
    if did not in users:
        return jsonify({"error": "User not found"}), 404
    
    # Get posts by this user (excluding comments and hidden posts)
    user_posts = [post for post in posts.values() 
                  if post["did"] == did and not post.get("parent_id") and not post.get("hidden", False)]
    
    # Sort by timestamp (newest first)
    sorted_posts = sorted(user_posts, key=lambda x: x["timestamp"], reverse=True)
    enriched = [enrich_post_with_current_user_fields(p) for p in sorted_posts]
    
    return jsonify({
        "posts": enriched,
        "total": len(sorted_posts),
        "user": {
            "did": did,
            "username": users[did]["username"],
            "display_name": users[did].get("display_name", users[did]["username"])
        }
    })

# Twitter-like tabs: likes, replies, media
@app.route("/api/user/<did>/likes", methods=["GET"])
def get_user_likes(did):
    if did not in users:
        return jsonify({"error": "User not found"}), 404
    liked_posts = [p for p in posts.values() if did in p.get("liked_by", []) and not p.get("hidden", False)]
    sorted_posts = sorted(liked_posts, key=lambda x: x["timestamp"], reverse=True)
    enriched = [enrich_post_with_current_user_fields(p) for p in sorted_posts]
    return jsonify({"posts": enriched, "total": len(sorted_posts)})

@app.route("/api/user/<did>/replies", methods=["GET"])
def get_user_replies(did):
    if did not in users:
        return jsonify({"error": "User not found"}), 404
    reply_posts = [p for p in posts.values() if p.get("parent_id") and p.get("did") == did and not p.get("hidden", False)]
    sorted_posts = sorted(reply_posts, key=lambda x: x["timestamp"], reverse=True)
    enriched = [enrich_post_with_current_user_fields(p) for p in sorted_posts]
    return jsonify({"posts": enriched, "total": len(sorted_posts)})

@app.route("/api/user/<did>/media", methods=["GET"])
def get_user_media(did):
    if did not in users:
        return jsonify({"error": "User not found"}), 404
    media_posts = [p for p in posts.values() if p.get("did") == did and not p.get("parent_id") and p.get("file_info") and not p.get("hidden", False)]
    sorted_posts = sorted(media_posts, key=lambda x: x["timestamp"], reverse=True)
    enriched = [enrich_post_with_current_user_fields(p) for p in sorted_posts]
    return jsonify({"posts": enriched, "total": len(sorted_posts)})

@app.route("/api/post/<post_id>", methods=["GET", "DELETE"])
def post_detail(post_id):
    if request.method == "GET":
        post = posts.get(post_id)
        if not post:
            return jsonify({"error": "Post not found"}), 404
        
        replies = [p for p in posts.values() if p.get("parent_id") == post_id]
        
        return jsonify({
            "post": post,
            "replies": sorted(replies, key=lambda x: x["timestamp"], reverse=True)
        })
    
    elif request.method == "DELETE":
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 403
        
        post = posts.get(post_id)
        if not post:
            return jsonify({"error": "Post not found"}), 404
        
        if post["did"] != payload["did"]:
            return jsonify({"error": "Unauthorized to delete this post"}), 403
        
        if post.get("parent_id") and post["parent_id"] in posts:
            posts[post["parent_id"]]["replies_count"] = max(0, posts[post["parent_id"]].get("replies_count", 0) - 1)
        
        del posts[post_id]
        save_metadata(POSTS_METADATA_FILE, posts)
        return jsonify({"message": "Post deleted"})

@app.route("/api/post/<post_id>/comments", methods=["GET"])
def get_comments(post_id):
    """Get all comments for a specific post"""
    post = posts.get(post_id)
    if not post:
        return jsonify({"error": "Post not found"}), 404
    
    # Get all comments (posts with parent_id = post_id) excluding hidden
    comments = [p for p in posts.values() if p.get("parent_id") == post_id and not p.get("hidden", False)]
    
    # Sort by timestamp (newest first) and enrich with current user fields
    sorted_comments = sorted(comments, key=lambda x: x["timestamp"], reverse=True)
    enriched = [enrich_post_with_current_user_fields(c) for c in sorted_comments]
    
    return jsonify({
        "post_id": post_id,
        "comments": enriched,
        "count": len(sorted_comments)
    })

@app.route("/api/post/<post_id>/comment", methods=["POST"])
def add_comment(post_id):
    """Add a comment to a post"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        # Fallbacks: support token passed via form-data or JSON (some clients may not send Authorization)
        try:
            token = (
                request.form.get("token")
                or request.args.get("token")
                or (request.get_json(silent=True) or {}).get("token", "")
                or request.headers.get("X-Auth-Token", "")
            )
        except Exception:
            token = ""
    payload = decode_jwt(token)
    if not payload:
        # As a compatibility fallback, accept DID sent explicitly (older clients)
        fallback_did = (
            request.form.get("did")
            or request.args.get("did")
            or (request.get_json(silent=True) or {}).get("did")
        )
        if fallback_did and fallback_did in users:
            payload = {"did": fallback_did}
        else:
            print("add_comment: missing/invalid token; headers:", dict(request.headers))
            return jsonify({"error": "Invalid or expired token"}), 403

    # Check if parent post exists
    parent_post = posts.get(post_id)
    if not parent_post:
        return jsonify({"error": "Post not found"}), 404

    did = payload["did"]
    content = request.form.get("content", "")
    file = request.files.get("file")

    if not content and not file:
        return jsonify({"error": "Comment content or file required"}), 400

    # Handle file upload for comment
    file_data = None
    file_info = None
    
    if file:
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
            
        if not allowed_file(file.filename):
            return jsonify({"error": "Invalid file type. Allowed: PNG, JPG, JPEG, GIF, WebP, MP4, MOV, AVI, MKV, WebM"}), 400
        
        # Check file size
        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({"error": f"File too large. Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB"}), 400
        
        # Read file data
        file_data = file.read()
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        
        # Determine file type
        if is_image_file(file.filename):
            file_type = "image"
        elif is_video_file(file.filename):
            file_type = "video"
        else:
            file_type = "file"
        
        file_info = {
            "filename": secure_filename(file.filename),
            "type": file_type,
            "extension": file_extension,
            "size": file_size
        }

        # Upload file if present (IPFS-only, no local storage)
    cid = None
    preview_url = None
    
    if file_data:
        upload_data = file_data
        filename = f"comment_{datetime.datetime.now().timestamp()}"
        if file_info:
            filename += f".{file_info['extension']}"

        # Upload directly to IPFS - no local storage
        cid = upload_to_ipfs(upload_data, filename=filename)
        if not cid:
            return jsonify({"error": "IPFS upload failed. Please ensure IPFS is running and try again."}), 500
        
        # IPFS upload successful
        preview_url = f"https://ipfs.io/ipfs/{cid}"
        print(f"✅ Comment file uploaded directly to IPFS: {cid}")

    # Create comment
    comment_id = str(uuid.uuid4())
    comment = {
        "id": comment_id,
        "did": did,
        "username": users[did]["username"],
        "content": content,
        "cid": cid,
        "preview": preview_url,
        "timestamp": datetime.datetime.now().isoformat(),
        "likes": 0,
        "parent_id": post_id,
        "replies_count": 0,
        "file_info": file_info,
        "liked_by": []
    }
    
    # Add comment to posts
    posts[comment_id] = comment
    
    # Update parent post's reply count
    parent_post["replies_count"] = parent_post.get("replies_count", 0) + 1
    
    save_metadata(POSTS_METADATA_FILE, posts)


    
    return jsonify({
        "message": "Comment added",
        "comment": comment
    })

@app.route("/api/search", methods=["GET"])
def search_posts():
    query = request.args.get("q", "").lower()
    if not query or len(query) < 3:
        return jsonify({"error": "Query must be at least 3 characters"}), 400
    
    results = [
        p for p in posts.values() 
        if query in p["content"].lower() or 
           query in p["username"].lower()
    ]
    return jsonify(sorted(results, key=lambda x: x["timestamp"], reverse=True))

@app.route("/api/like/<post_id>", methods=["POST"])
def like_post(post_id):
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 403
        
        post = posts.get(post_id)
        if not post:
            return jsonify({"error": "Post not found"}), 404
        
        did = payload["did"]
        
        # Initialize likes and liked_by if they don't exist
        if "likes" not in post:
            post["likes"] = 0
        if "liked_by" not in post:
            post["liked_by"] = []
        
        # Check if user already liked this post
        if did in post["liked_by"]:
            return jsonify({"error": "Already liked this post"}), 400
        
        # Like the post
        post["likes"] += 1
        post["liked_by"].append(did)
        
        # Save to metadata
        save_metadata(POSTS_METADATA_FILE, posts)
        
        return jsonify({
            "message": "Post liked",
            "likes": post["likes"]
        })
        
    except Exception as e:
        print(f"Error in like_post: {str(e)}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/api/unlike/<post_id>", methods=["POST"])
def unlike_post(post_id):
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 403
        
        post = posts.get(post_id)
        if not post:
            return jsonify({"error": "Post not found"}), 404
        
        did = payload["did"]
        
        # Initialize likes and liked_by if they don't exist
        if "likes" not in post:
            post["likes"] = 0
        if "liked_by" not in post:
            post["liked_by"] = []
        
        # Check if user has liked this post
        if did not in post["liked_by"]:
            return jsonify({"error": "You haven't liked this post"}), 400
        
        # Unlike the post
        post["likes"] = max(0, post["likes"] - 1)
        post["liked_by"].remove(did)
        
        # Save to metadata
        save_metadata(POSTS_METADATA_FILE, posts)
        
        return jsonify({
            "message": "Post unliked",
            "likes": post["likes"]
        })
        
    except Exception as e:
        print(f"Error in unlike_post: {str(e)}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

# ==== Share System Routes ====
@app.route("/api/share/<post_id>", methods=["POST"])
def share_post(post_id):
    """Share a post to other platforms or users"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 403
    
    # Check if original post exists
    original_post = posts.get(post_id)
    if not original_post:
        return jsonify({"error": "Post not found"}), 404
    
    did = payload["did"]
    platform = request.form.get("platform", "general")  # twitter, facebook, linkedin, general
    message = request.form.get("message", "")  # Optional custom message
    
    # Check if user already shared this post
    if "shared_by" not in original_post:
        original_post["shared_by"] = []
    
    if did in original_post["shared_by"]:
        return jsonify({"error": "Already shared this post"}), 400
    
    # Create share record
    share_id = str(uuid.uuid4())
    share = {
        "id": share_id,
        "post_id": post_id,
        "user_did": did,
        "username": users[did]["username"],
        "platform": platform,
        "message": message,
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    # Add to shares metadata
    if did not in shares_metadata:
        shares_metadata[did] = []
    shares_metadata[did].append(share)
    
    # Update post share count
    original_post["shares_count"] = original_post.get("shares_count", 0) + 1
    original_post["shared_by"].append(did)
    
    save_metadata(SHARES_METADATA_FILE, shares_metadata)
    save_metadata(POSTS_METADATA_FILE, posts)
    
    return jsonify({
        "message": "Post shared successfully",
        "share": share,
        "post_shares_count": original_post["shares_count"]
    })

@app.route("/api/shares/<did>", methods=["GET"])
def get_user_shares(did):
    """Get all shares by a specific user"""
    if did not in users:
        return jsonify({"error": "User not found"}), 404
    
    user_shares = shares_metadata.get(did, [])
    return jsonify({
        "shares": user_shares,
        "count": len(user_shares)
    })

@app.route("/api/shares/post/<post_id>", methods=["GET"])
def get_post_shares(post_id):
    """Get all shares of a specific post"""
    post = posts.get(post_id)
    if not post:
        return jsonify({"error": "Post not found"}), 404
    
    # Collect all shares for this post
    all_shares = []
    for user_shares in shares_metadata.values():
        for share in user_shares:
            if share.get("post_id") == post_id:
                all_shares.append(share)
    
    # Sort by timestamp (newest first)
    sorted_shares = sorted(all_shares, key=lambda x: x["timestamp"], reverse=True)
    
    return jsonify({
        "post_id": post_id,
        "shares": sorted_shares,
        "count": len(sorted_shares)
    })

@app.route("/api/repost/<post_id>", methods=["POST"])
def repost_post(post_id):
    """Create a repost of an existing post. Supports optional quote text and file."""
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 403

        original_post = posts.get(post_id)
        if not original_post:
            return jsonify({"error": "Post not found"}), 404

        did = payload["did"]

        # Read optional quote content and file
        content = request.form.get("content", "")
        file = request.files.get("file")

        file_data = None
        file_info = None
        if file:
            if file.filename == '':
                return jsonify({"error": "No file selected"}), 400
            if not allowed_file(file.filename):
                return jsonify({"error": "Invalid file type. Allowed: PNG, JPG, JPEG, GIF, WebP, MP4, MOV, AVI, MKV, WebM"}), 400
            file.seek(0, 2)
            file_size = file.tell()
            file.seek(0)
            if file_size > MAX_FILE_SIZE:
                return jsonify({"error": f"File too large. Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB"}), 400
            file_data = file.read()
            file_extension = file.filename.rsplit('.', 1)[1].lower()
            if is_image_file(file.filename):
                file_type = "image"
            elif is_video_file(file.filename):
                file_type = "video"
            else:
                file_type = "file"
            file_info = {
                "filename": secure_filename(file.filename),
                "type": file_type,
                "extension": file_extension,
                "size": file_size
            }

        # Upload optional file or quote content to IPFS/local for traceability
        cid = None
        preview_url = None
        if file_data:
            filename = f"repost_{datetime.datetime.now().timestamp()}"
            if file_info:
                filename += f".{file_info['extension']}"
            cid = upload_to_ipfs(file_data, filename=filename)
            if not cid:
                return jsonify({"error": "File upload failed"}), 500
            preview_url = f"https://ipfs.io/ipfs/{cid}"

        # Build new repost entry
        repost_id = str(uuid.uuid4())
        user_record = users.get(did, {"username": "unknown"})
        repost_post_obj = {
            "id": repost_id,
            "did": did,
            "username": user_record["username"],
            "display_name": user_record.get("display_name", user_record["username"]),
            "avatar": user_record.get("avatar", ""),
            "content": content,
            "cid": cid,
            "preview": preview_url,
            "file_url": preview_url if file_info else None,
            "file_type": file_info["type"] if file_info else None,
            "timestamp": datetime.datetime.now().isoformat(),
            "likes": 0,
            "parent_id": None,
            "replies_count": 0,
            "file_info": file_info,
            "shares_count": 0,
            "liked_by": [],
            "hidden": False,
            # Repost-specific fields
            "is_repost": True,
            "repost_of": post_id,
            "original_post": {
                "id": original_post["id"],
                "username": original_post.get("username"),
                "display_name": original_post.get("display_name", original_post.get("username")),
                "content": original_post.get("content"),
                "timestamp": original_post.get("timestamp"),
                "file_info": original_post.get("file_info"),
                "preview": original_post.get("preview")
            }
        }

        # Save repost
        posts[repost_id] = repost_post_obj

        # Update original post stats
        if "reposts_count" not in original_post:
            original_post["reposts_count"] = 0
        if "reposted_by" not in original_post:
            original_post["reposted_by"] = []
        if did not in original_post["reposted_by"]:
            original_post["reposted_by"].append(did)
            original_post["reposts_count"] += 1

        save_metadata(POSTS_METADATA_FILE, posts)

        return jsonify({
            "message": "Repost created",
            "repost": repost_post_obj
        })
    except Exception as e:
        print(f"Error in repost_post: {str(e)}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/api/unrepost/<post_id>", methods=["POST"])
def unrepost_post(post_id):
    """Remove the current user's repost of a given original post."""
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 403

        did = payload["did"]

        # Find the user's repost post referencing this original post
        repost_to_delete_id = None
        for p_id, p in posts.items():
            if p.get("is_repost") and p.get("repost_of") == post_id and p.get("did") == did:
                repost_to_delete_id = p_id
                break

        if not repost_to_delete_id:
            return jsonify({"error": "Repost not found"}), 404

        # Delete the repost
        del posts[repost_to_delete_id]

        # Update original post stats
        original_post = posts.get(post_id)
        if original_post:
            if "reposted_by" in original_post and did in original_post["reposted_by"]:
                try:
                    original_post["reposted_by"].remove(did)
                except ValueError:
                    pass
            if "reposts_count" in original_post:
                original_post["reposts_count"] = max(0, original_post.get("reposts_count", 0) - 1)

        save_metadata(POSTS_METADATA_FILE, posts)

        return jsonify({
            "message": "Repost removed",
            "post_id": post_id
        })
    except Exception as e:
        print(f"Error in unrepost_post: {str(e)}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/api/post/<post_id>/hide", methods=["POST"])
def hide_post(post_id):
    """Hide a post from the user's view"""
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            try:
                token = (
                    request.form.get("token")
                    or request.args.get("token")
                    or (request.get_json(silent=True) or {}).get("token", "")
                    or request.headers.get("X-Auth-Token", "")
                )
            except Exception:
                token = ""
        payload = decode_jwt(token)
        if not payload:
            fallback_did = (
                request.form.get("did")
                or request.args.get("did")
                or (request.get_json(silent=True) or {}).get("did")
            )
            if fallback_did and fallback_did in users:
                payload = {"did": fallback_did}
            else:
                return jsonify({"error": "Invalid or expired token"}), 403
        
        post = posts.get(post_id)
        if not post:
            return jsonify({"error": "Post not found"}), 404
        
        # Only post owner can hide their own posts
        if post["did"] != payload["did"]:
            return jsonify({"error": "Unauthorized to hide this post"}), 403
        
        post["hidden"] = True

        # If this is a comment, decrement the parent's replies_count
        parent_id = post.get("parent_id")
        if parent_id and parent_id in posts:
            parent = posts[parent_id]
            parent["replies_count"] = max(0, parent.get("replies_count", 0) - 1)
        save_metadata(POSTS_METADATA_FILE, posts)
        
        return jsonify({
            "message": "Post hidden successfully",
            "post_id": post_id
        })
        
    except Exception as e:
        print(f"Error in hide_post: {str(e)}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/api/post/<post_id>/unhide", methods=["POST"])
def unhide_post(post_id):
    """Unhide a post"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        try:
            token = (
                request.form.get("token")
                or request.args.get("token")
                or (request.get_json(silent=True) or {}).get("token", "")
                or request.headers.get("X-Auth-Token", "")
            )
        except Exception:
            token = ""
    payload = decode_jwt(token)
    if not payload:
        fallback_did = (
            request.form.get("did")
            or request.args.get("did")
            or (request.get_json(silent=True) or {}).get("did")
        )
        if fallback_did and fallback_did in users:
            payload = {"did": fallback_did}
        else:
            return jsonify({"error": "Invalid or expired token"}), 403
    
    post = posts.get(post_id)
    if not post:
        return jsonify({"error": "Post not found"}), 404
    
    # Only post owner can unhide their own posts
    if post["did"] != payload["did"]:
        return jsonify({"error": "Unauthorized to unhide this post"}), 403
    
    post["hidden"] = False
    save_metadata(POSTS_METADATA_FILE, posts)
    
    return jsonify({
        "message": "Post unhidden successfully",
        "post_id": post_id
    })

@app.route("/api/unshare/<post_id>", methods=["POST"])
def unshare_post(post_id):
    """Remove a share"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 403
    
    did = payload["did"]
    
    # Find and remove the share
    if did in shares_metadata:
        shares_metadata[did] = [s for s in shares_metadata[did] if s.get("post_id") != post_id]
    
    # Update post share count
    post = posts.get(post_id)
    if post and did in post.get("shared_by", []):
        post["shared_by"].remove(did)
        post["shares_count"] = max(0, post.get("shares_count", 0) - 1)
        save_metadata(POSTS_METADATA_FILE, posts)
    
    save_metadata(SHARES_METADATA_FILE, shares_metadata)
    
    return jsonify({
        "message": "Share removed successfully",
        "post_shares_count": post.get("shares_count", 0) if post else 0
    })

# ==== Social Routes ====
@app.route("/api/follow/<target_did>", methods=["POST"])
def follow_user(target_did):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 403

    did = payload["did"]
    if target_did not in users or did == target_did:
        return jsonify({"error": "Invalid user"}), 400

    if did in followers.get(target_did, set()):
        return jsonify({"error": "Already following this user"}), 400

    followers.setdefault(target_did, set()).add(did)
    following.setdefault(did, set()).add(target_did)

    save_metadata(FOLLOWERS_METADATA_FILE, followers)
    save_metadata(FOLLOWING_METADATA_FILE, following)

    return jsonify({
        "message": f"Now following {users[target_did]['username']}",
        "following": list(following[did])
    })

@app.route("/api/unfollow/<target_did>", methods=["POST"])
def unfollow_user(target_did):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid token"}), 403

    did = payload["did"]
    if target_did not in users or did == target_did:
        return jsonify({"error": "Invalid user"}), 400

    if did not in followers.get(target_did, set()):
        return jsonify({"error": "Not following this user"}), 400

    followers[target_did].discard(did)
    following[did].discard(target_did)

    save_metadata(FOLLOWERS_METADATA_FILE, followers)
    save_metadata(FOLLOWING_METADATA_FILE, following)

    return jsonify({
        "message": f"Unfollowed {users[target_did]['username']}",
        "following": list(following[did])
    })

@app.route("/api/followers/<did>", methods=["GET"])
def get_followers(did):
    if did not in users:
        return jsonify({"error": "User not found"}), 404
    
    followers_list = []
    for follower_did in followers.get(did, set()):
        follower = users.get(follower_did)
        if follower:
            followers_list.append({
                "did": follower_did,
                "username": follower.get("username", ""),
                "displayName": follower.get("display_name", follower.get("username", "")),
                "avatar": follower.get("avatar", ""),
                "bio": follower.get("bio", "")
            })
    
    return jsonify({
        "followers": followers_list,
        "count": len(followers_list)
    })

@app.route("/api/following/<did>", methods=["GET"])
def get_following(did):
    if did not in users:
        return jsonify({"error": "User not found"}), 404
    
    following_list = []
    for following_did in following.get(did, set()):
        user = users.get(following_did)
        if user:
            following_list.append({
                "did": following_did,
                "username": user.get("username", ""),
                "displayName": user.get("display_name", user.get("username", "")),
                "avatar": user.get("avatar", ""),
                "bio": user.get("bio", "")
            })
    
    return jsonify({
        "following": following_list,
        "count": len(following_list)
    })

# ==== AI Assistant Routes ====
import sys
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from data.Gemini import gemini_service
except ImportError:
    # Fallback if Gemini service is not available
    gemini_service = None

@app.route("/api/ai/chat", methods=["POST"])
def ai_chat():
    """Send a message to the AI assistant."""
    if not gemini_service:
        return jsonify({"error": "AI service not available"}), 503
        
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 403

    user_id = payload["did"]
    data = request.get_json()
    message = data.get("message")
    
    if not message:
        return jsonify({"error": "Message is required"}), 400
    
    if len(message.strip()) == 0:
        return jsonify({"error": "Message cannot be empty"}), 400
    
    try:
        response = gemini_service.send_message(user_id, message)
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ai/history", methods=["GET"])
def get_ai_history():
    """Get the AI chat history for the authenticated user."""
    if not gemini_service:
        return jsonify({"error": "AI service not available"}), 503
        
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 403

    user_id = payload["did"]
    
    try:
        history = gemini_service.get_chat_history(user_id)
        return jsonify({"history": history})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ai/clear", methods=["POST"])
def clear_ai_chat():
    """Clear the AI chat history for the authenticated user."""
    if not gemini_service:
        return jsonify({"error": "AI service not available"}), 503
        
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 403

    user_id = payload["did"]
    
    try:
        result = gemini_service.clear_chat(user_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ai/stats", methods=["GET"])
def get_ai_stats():
    """Get AI chat statistics for the authenticated user."""
    if not gemini_service:
        return jsonify({"error": "AI service not available"}), 503
        
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 403

    user_id = payload["did"]
    
    try:
        stats = gemini_service.get_chat_stats(user_id)
        return jsonify({"stats": stats})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ai/models", methods=["GET"])
def get_ai_models():
    """Get available AI models."""
    if not gemini_service:
        return jsonify({"error": "AI service not available"}), 503
        
    try:
        models = gemini_service.get_available_models()
        return jsonify({"models": models})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ai/health", methods=["GET"])
def ai_health_check():
    """Check AI service health."""
    if not gemini_service:
        return jsonify({
            "status": "unavailable",
            "error": "AI service not installed",
            "service": "NEXA AI Assistant"
        }), 503
        
    try:
        # Test if the service is working
        test_response = gemini_service.send_message("test_user", "Hello")
        return jsonify({
            "status": "healthy",
            "service": "NEXA AI Assistant",
            "model": "Gemini 2.0 Flash"
        })
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "service": "NEXA AI Assistant"
        }), 500

# ==== Settings Routes ====
@app.route("/api/settings/<did>", methods=["GET", "POST"])
def user_settings(did):
    """Get or update user settings"""
    if request.method == "GET":
        # Verify user exists
        if did not in users:
            return jsonify({"error": "User not found"}), 404
        
        # Return user settings
        user_settings = settings_metadata.get(did, {})
        return jsonify({
            "settings": user_settings,
            "user": {
                "did": did,
                "username": users[did]["username"]
            }
        })
    
    elif request.method == "POST":
        # Verify token and authorization
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        payload = decode_jwt(token)
        if not payload or payload["did"] != did:
            return jsonify({"error": "Unauthorized"}), 403
        
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "No settings data provided"}), 400
            
            # Update settings
            current_settings = settings_metadata.get(did, {})
            
            # Update theme
            if "theme" in data:
                current_settings["theme"] = data["theme"]
            
            # Update font size
            if "font_size" in data:
                current_settings["font_size"] = data["font_size"]
            
            # Update notifications
            if "notifications" in data:
                if "notifications" not in current_settings:
                    current_settings["notifications"] = {}
                current_settings["notifications"].update(data["notifications"])
            
            # Update privacy
            if "privacy" in data:
                if "privacy" not in current_settings:
                    current_settings["privacy"] = {}
                current_settings["privacy"].update(data["privacy"])
            
            # Update security
            if "security" in data:
                if "security" not in current_settings:
                    current_settings["security"] = {}
                current_settings["security"].update(data["security"])
            
            # Update content preferences
            if "content" in data:
                if "content" not in current_settings:
                    current_settings["content"] = {}
                current_settings["content"].update(data["content"])
            
            # Save settings
            settings_metadata[did] = current_settings
            save_metadata(SETTINGS_METADATA_FILE, settings_metadata)
            
            return jsonify({
                "message": "Settings updated successfully",
                "settings": current_settings
            })
            
        except Exception as e:
            print(f"Error updating settings: {str(e)}")
            return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/api/settings/<did>/reset", methods=["POST"])
def reset_settings(did):
    """Reset user settings to defaults"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = decode_jwt(token)
    if not payload or payload["did"] != did:
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        # Reset to default settings
        settings_metadata[did] = {
            "theme": "dark",
            "font_size": "medium",
            "notifications": {
                "push_notifications": True,
                "new_followers": True,
                "mentions": True,
                "likes": True,
                "comments": True,
                "shares": True
            },
            "privacy": {
                "enhanced_privacy": False,
                "show_online_status": True,
                "allow_direct_messages": True,
                "show_following_list": True
            },
            "security": {
                "two_factor_enabled": False,
                "login_notifications": True,
                "session_timeout": 24
            },
            "content": {
                "auto_play_videos": True,
                "show_sensitive_content": False,
                "language": "en"
            }
        }
        
        save_metadata(SETTINGS_METADATA_FILE, settings_metadata)
        
        return jsonify({
            "message": "Settings reset to defaults",
            "settings": settings_metadata[did]
        })
        
    except Exception as e:
        print(f"Error resetting settings: {str(e)}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/api/settings/<did>/export", methods=["GET"])
def export_settings(did):
    """Export user settings as JSON"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = decode_jwt(token)
    if not payload or payload["did"] != did:
        return jsonify({"error": "Unauthorized"}), 403
    
    try:
        user_settings = settings_metadata.get(did, {})
        return jsonify({
            "user_did": did,
            "username": users[did]["username"],
            "export_date": datetime.datetime.now().isoformat(),
            "settings": user_settings
        })
        
    except Exception as e:
        print(f"Error exporting settings: {str(e)}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/api/users/suggested", methods=["GET"])
def get_suggested_users():
    """Get suggested users to follow"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = decode_jwt(token)
    
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 403
    
    current_user_did = payload["did"]
    
    # Get users that the current user is not following
    following_users = following.get(current_user_did, set())
    suggested_users = []
    
    for did, user_data in users.items():
        if did != current_user_did and did not in following_users:
            # Calculate user score based on activity
            user_posts = [p for p in posts.values() if p["did"] == did]
            user_followers = len(followers.get(did, set()))
            
            suggested_users.append({
                "did": did,
                "username": user_data["username"],
                "displayName": user_data.get("display_name", user_data["username"]),
                "avatar": user_data.get("avatar", ""),
                "bio": user_data.get("bio", ""),
                "posts_count": len(user_posts),
                "followers_count": user_followers,
                "score": len(user_posts) + user_followers  # Simple scoring
            })
    
    # Sort by score and return top 10
    suggested_users.sort(key=lambda x: x["score"], reverse=True)
    top_suggestions = suggested_users[:10]
    
    return jsonify({
        "users": top_suggestions,
        "count": len(top_suggestions)
    })

# ==== Notifications Routes ====
@app.route("/api/notifications", methods=["GET"])
def get_notifications():
    """Get notifications for the authenticated user"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 403

    user_did = payload["did"]
    user_notifications = notifications_metadata.get(user_did, [])
    
    # Sort by timestamp (newest first)
    sorted_notifications = sorted(user_notifications, key=lambda x: x["timestamp"], reverse=True)
    
    return jsonify({
        "notifications": sorted_notifications,
        "count": len(sorted_notifications)
    })

@app.route("/api/notifications/<notification_id>/read", methods=["POST"])
def mark_notification_read(notification_id):
    """Mark a notification as read"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = decode_jwt(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 403

    user_did = payload["did"]
    user_notifications = notifications_metadata.get(user_did, [])
    
    # Find and mark the notification as read
    for notification in user_notifications:
        if notification["id"] == notification_id:
            notification["read"] = True
            break
    
    notifications_metadata[user_did] = user_notifications
    save_metadata(NOTIFICATIONS_METADATA_FILE, notifications_metadata)
    
    return jsonify({
        "message": "Notification marked as read",
        "notification_id": notification_id
    })

def create_notification(user_did: str, notification_type: str, message: str, related_user_id: str = None, post_id: str = None):
    """Create a new notification for a user"""
    notification = {
        "id": str(uuid.uuid4()),
        "type": notification_type,
        "message": message,
        "timestamp": datetime.datetime.now().isoformat(),
        "read": False,
        "userId": related_user_id,
        "postId": post_id
    }
    
    if user_did not in notifications_metadata:
        notifications_metadata[user_did] = []
    
    notifications_metadata[user_did].append(notification)
    save_metadata(NOTIFICATIONS_METADATA_FILE, notifications_metadata)
    
    return notification

def get_ipfs_gateway_download(cid):
    """Get file content from IPFS gateway"""
    try:
        import requests
        gateway_url = f"https://ipfs.io/ipfs/{cid}"
        response = requests.get(gateway_url, timeout=30)
        if response.status_code == 200:
            return response.content
        else:
            print(f"IPFS gateway download error: {response.status_code}")
            return None
    except Exception as e:
        print(f"IPFS gateway download error: {e}")
        return None

# ==== Server Startup ====
if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    
    print("🚀 Starting Nexa application...")
    print("🌐 Main API: http://0.0.0.0:5000")
    
    # Start the main Flask app
    app.run(host="0.0.0.0", port=5000, debug=True)
