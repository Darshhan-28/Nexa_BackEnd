from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os

"""
Run the Nexa backend API and serve the built frontend (Vite) assets.
This file uses an absolute path for the static folder so it works regardless of CWD.
"""

# Import backend logic
import nexa

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend", "project", "dist"))

app = Flask(__name__, static_folder=STATIC_DIR)
CORS(app)
app.config["SECRET_KEY"] = "nexa_secret_key"

# ==== Serve Frontend ====
@app.route("/")
def serve_index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/<path:path>")
def serve_static(path):
    # If the requested path does not exist, serve index.html (for SPA routing)
    if not os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, "index.html")
    return send_from_directory(app.static_folder, path)

# ==== API Routes ====
app.add_url_rule("/api/register", view_func=nexa.register, methods=["POST"])
app.add_url_rule("/api/login", view_func=nexa.login, methods=["POST"])
app.add_url_rule("/api/profile/<did>", view_func=nexa.profile, methods=["GET", "POST"])
app.add_url_rule("/api/post", view_func=nexa.create_post, methods=["POST"])
app.add_url_rule("/api/posts", view_func=nexa.get_posts, methods=["GET"])
app.add_url_rule("/api/user/<did>/posts", view_func=nexa.get_user_posts, methods=["GET"])
app.add_url_rule("/api/post/<post_id>", view_func=nexa.post_detail, methods=["GET", "DELETE"])
app.add_url_rule("/api/post/<post_id>/comments", view_func=nexa.get_comments, methods=["GET"])
app.add_url_rule("/api/post/<post_id>/comment", view_func=nexa.add_comment, methods=["POST"])
app.add_url_rule("/api/post/<post_id>/hide", view_func=nexa.hide_post, methods=["POST"])
app.add_url_rule("/api/post/<post_id>/unhide", view_func=nexa.unhide_post, methods=["POST"])
app.add_url_rule("/api/search", view_func=nexa.search_posts, methods=["GET"])
app.add_url_rule("/api/like/<post_id>", view_func=nexa.like_post, methods=["POST"])
app.add_url_rule("/api/unlike/<post_id>", view_func=nexa.unlike_post, methods=["POST"])
app.add_url_rule("/api/follow/<target_did>", view_func=nexa.follow_user, methods=["POST"])
app.add_url_rule("/api/unfollow/<target_did>", view_func=nexa.unfollow_user, methods=["POST"])
app.add_url_rule("/api/followers/<did>", view_func=nexa.get_followers, methods=["GET"])
app.add_url_rule("/api/following/<did>", view_func=nexa.get_following, methods=["GET"])
app.add_url_rule("/api/users/suggested", view_func=nexa.get_suggested_users, methods=["GET"])
app.add_url_rule("/api/notifications", view_func=nexa.get_notifications, methods=["GET"])
app.add_url_rule("/api/notifications/<notification_id>/read", view_func=nexa.mark_notification_read, methods=["POST"])
app.add_url_rule("/api/share/<post_id>", view_func=nexa.share_post, methods=["POST"])
app.add_url_rule("/api/shares/<did>", view_func=nexa.get_user_shares, methods=["GET"])
app.add_url_rule("/api/shares/post/<post_id>", view_func=nexa.get_post_shares, methods=["GET"])
app.add_url_rule("/api/unshare/<post_id>", view_func=nexa.unshare_post, methods=["POST"])
app.add_url_rule("/api/ai/chat", view_func=nexa.ai_chat, methods=["POST"])
app.add_url_rule("/api/ai/history", view_func=nexa.get_ai_history, methods=["GET"])
app.add_url_rule("/api/ai/clear", view_func=nexa.clear_ai_chat, methods=["POST"])
app.add_url_rule("/api/ai/stats", view_func=nexa.get_ai_stats, methods=["GET"])
app.add_url_rule("/api/ai/models", view_func=nexa.get_ai_models, methods=["GET"])
app.add_url_rule("/api/ai/health", view_func=nexa.ai_health_check, methods=["GET"])
app.add_url_rule("/api/settings/<did>", view_func=nexa.user_settings, methods=["GET", "POST"])
app.add_url_rule("/api/settings/<did>/reset", view_func=nexa.reset_settings, methods=["POST"])
app.add_url_rule("/api/settings/<did>/export", view_func=nexa.export_settings, methods=["GET"])

app.add_url_rule("/api/upload-avatar", view_func=nexa.upload_avatar, methods=["POST"])
app.add_url_rule("/api/upload-cover", view_func=nexa.upload_cover, methods=["POST"])
app.add_url_rule("/api/migrate-to-ipfs", view_func=nexa.migrate_to_ipfs, methods=["POST"])

app.add_url_rule("/api/ipfs/<cid>", view_func=nexa.serve_ipfs_file, methods=["GET"])
# Pinning endpoint
app.add_url_rule("/api/pin/<cid>", view_func=nexa.pin_cid, methods=["POST"])
# Removed uploads route - files are now served from IPFS only

# Add route for deleting all hidden posts
app.add_url_rule('/api/delete-hidden-posts', 'delete_hidden_posts', nexa.delete_all_hidden_posts, methods=['POST'])



# ==== Run Server ====
if __name__ == "__main__":
    print("🚀 Starting Nexa application...")
    print("🌐 Main API: http://0.0.0.0:5000")
    
    app.run(host="0.0.0.0", port=5000, debug=True)
