#!/usr/bin/env python3
"""
Script to clear posts with broken IPFS links
"""

import json
import os

POSTS_METADATA_FILE = "posts_metadata.json"

def clear_broken_posts():
    """Remove posts that have IPFS links that are not working"""
    
    if not os.path.exists(POSTS_METADATA_FILE):
        print("No posts metadata file found")
        return
    
    with open(POSTS_METADATA_FILE, 'r') as f:
        posts = json.load(f)
    
    # Convert to dict if it's a list
    if isinstance(posts, list):
        posts = {post['id']: post for post in posts}
    
    # Find posts with IPFS links
    broken_posts = []
    for post_id, post in posts.items():
        if post.get('preview', '').startswith('https://ipfs.io/ipfs/'):
            broken_posts.append(post_id)
    
    if not broken_posts:
        print("No posts with IPFS links found")
        return
    
    print(f"Found {len(broken_posts)} posts with IPFS links")
    print("Removing these posts...")
    
    # Remove broken posts
    for post_id in broken_posts:
        del posts[post_id]
    
    # Save updated posts
    with open(POSTS_METADATA_FILE, 'w') as f:
        json.dump(posts, f, indent=2)
    
    print(f"Removed {len(broken_posts)} posts with broken IPFS links")
    print(f"Remaining posts: {len(posts)}")

if __name__ == "__main__":
    clear_broken_posts()
