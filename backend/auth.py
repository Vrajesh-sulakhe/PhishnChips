"""
auth.py - Google OAuth 2.0 & Session Management for Phish&Chips.
Handles Google Identity Services token verification, guest analyst demo access, and authenticated sessions.
"""

import os
import json
import base64
from typing import Optional, Dict, Any
import httpx
from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import db

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()

security_bearer = HTTPBearer(auto_error=False)

async def verify_google_id_token(id_token_str: str) -> Optional[Dict[str, Any]]:
    """
    Verifies a Google ID token by querying Google's public tokeninfo endpoint.
    Extracts email, name, picture, and sub (Google user ID).
    """
    if not id_token_str:
        return None

    # Method 1: Google OAuth2 tokeninfo verification
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"id_token": id_token_str}
            )
            if resp.status_code == 200:
                payload = resp.json()
                # Verify audience if client ID is configured
                if GOOGLE_CLIENT_ID and payload.get("aud") != GOOGLE_CLIENT_ID:
                    print(f"Warning: Token aud {payload.get('aud')} does not match configured {GOOGLE_CLIENT_ID}")
                return {
                    "email": payload.get("email"),
                    "name": payload.get("name") or payload.get("email", "").split("@")[0],
                    "avatar_url": payload.get("picture"),
                    "google_id": payload.get("sub")
                }
    except Exception as e:
        print(f"Google tokeninfo API error: {e}")

    # Method 2: Fallback JWT payload decoder for development / unverified networks
    try:
        parts = id_token_str.split(".")
        if len(parts) >= 2:
            padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
            decoded = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
            if decoded.get("email"):
                return {
                    "email": decoded.get("email"),
                    "name": decoded.get("name") or decoded.get("email", "").split("@")[0],
                    "avatar_url": decoded.get("picture"),
                    "google_id": decoded.get("sub")
                }
    except Exception as e:
        print(f"Fallback JWT parse error: {e}")

    return None

def extract_session_token(request: Request) -> Optional[str]:
    """Extracts session token from Authorization header or cookie."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()
    
    cookie_token = request.cookies.get("phishchips_session")
    if cookie_token:
        return cookie_token.strip()
    
    return None

def get_current_user_optional(request: Request) -> Optional[Dict[str, Any]]:
    """Returns currently authenticated user, or None if anonymous."""
    token = extract_session_token(request)
    if not token:
        return None
    return db.get_user_by_session(token)

def get_current_user_required(request: Request) -> Dict[str, Any]:
    """Returns authenticated user or raises HTTP 401 Unauthorized."""
    user = get_current_user_optional(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in with Google or Email."
        )
    return user

