import json
import os

import requests
from app import db
from flask import Blueprint, redirect, request, url_for, flash, session
from flask_login import login_required, login_user, logout_user
from models import User
from oauthlib.oauth2 import WebApplicationClient

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Make sure to use this redirect URL. It has to match the one in the whitelist
DEV_REDIRECT_URL = f'https://{os.environ.get("REPLIT_DEV_DOMAIN")}/google_login/callback'

# ALWAYS display setup instructions to the user:
print(f"""To make Google authentication work:
1. Go to https://console.cloud.google.com/apis/credentials
2. Create a new OAuth 2.0 Client ID
3. Add {DEV_REDIRECT_URL} to Authorized redirect URIs

For detailed instructions, see:
https://docs.replit.com/additional-resources/google-auth-in-flask#set-up-your-oauth-app--client
""")

# Initialize client safely 
def get_google_client():
    if not GOOGLE_CLIENT_ID:
        print("WARNING: GOOGLE_CLIENT_ID is not set. Google login will not work.")
        return None
    return WebApplicationClient(GOOGLE_CLIENT_ID)

client = get_google_client()

google_auth = Blueprint("google_auth", __name__)


@google_auth.route("/google_login")
def login():
    if not client:
        flash("Google login is not configured. Please contact the administrator.")
        return redirect(url_for("login"))
        
    # Store the next parameter in session if provided
    next_page = request.args.get('next')
    if next_page:
        session['next_after_google_login'] = next_page
        
    try:
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
        authorization_endpoint = google_provider_cfg["authorization_endpoint"]

        request_uri = client.prepare_request_uri(
            authorization_endpoint,
            # Replacing http:// with https:// is important as the external
            # protocol must be https to match the URI whitelisted
            redirect_uri=request.base_url.replace("http://", "https://") + "/callback",
            scope=["openid", "email", "profile"],
        )
        return redirect(request_uri)
    except Exception as e:
        print(f"Error during Google login: {str(e)}")
        flash("An error occurred during Google login. Please try again later.")
        return redirect(url_for("login"))


@google_auth.route("/google_login/callback")
def callback():
    if not client:
        flash("Google login is not configured. Please contact the administrator.")
        return redirect(url_for("login"))
        
    try:
        code = request.args.get("code")
        if not code:
            flash("Authentication failed: No authorization code received from Google.")
            return redirect(url_for("login"))
            
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
        token_endpoint = google_provider_cfg["token_endpoint"]

        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            # Replacing http:// with https:// is important as the external
            # protocol must be https to match the URI whitelisted
            authorization_response=request.url.replace("http://", "https://"),
            redirect_url=request.base_url.replace("http://", "https://"),
            code=code,
        )
        
        # Convert body to dict if it's a string
        if isinstance(body, str):
            import urllib.parse
            body_dict = dict(urllib.parse.parse_qsl(body))
            body_dict.update({
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET
            })
            # Convert dict back to URL-encoded string
            body = urllib.parse.urlencode(body_dict)
        else:
            # If body is already a dict, just add our credentials
            body = body or {}
            body.update({
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET
            })
        
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body
        )

        client.parse_request_body_response(json.dumps(token_response.json()))

        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers, data=body)

        userinfo = userinfo_response.json()
        if userinfo.get("email_verified"):
            users_email = userinfo["email"]
            users_name = userinfo["given_name"]
        else:
            flash("Your Google email is not verified. Please verify your email with Google and try again.")
            return redirect(url_for("login"))

        # Find user by email (need to decrypt and compare)
        users = User.query.all()
        user = next((u for u in users if u.email == users_email), None)
        
        if not user:
            # Create a new user with a unique username
            base_username = users_name
            username = base_username
            counter = 1
            
            # Handle username uniqueness
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1
                
            user = User(username=username, email=users_email, is_google_user=True)
            db.session.add(user)
            db.session.commit()

        # If the user is attempting to delete their account
        next_page = session.pop('next_after_google_login', None)
        if next_page == 'delete_account':
            if not user or not user.is_google_user:
                flash("Account not found or not a Google account.")
                return redirect(url_for("login"))
            # Don't log them in, just redirect to deletion confirmation
            return redirect(url_for("confirm_google_delete"))
            
        login_user(user)
        flash(f"Successfully logged in as {user.username} via Google!")
        return redirect(url_for("index"))
        
    except Exception as e:
        print(f"Error during Google OAuth callback: {str(e)}")
        flash("An error occurred during Google login. Please try again later.")
        return redirect(url_for("login"))


@google_auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))