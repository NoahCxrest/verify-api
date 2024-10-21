from flask import Flask, request, redirect, url_for, render_template
import requests
import pymongo
from decouple import config
import time
import logging
from dataclasses import dataclass
from typing import Optional, Tuple
from functools import wraps

@dataclass
class Settings:
    MONGO_URL: str = config('MONGO_URL')
    DATABASE: str = config('DATABASE')
    CLIENT_ID: int = config('CLIENT_ID')
    CLIENT_SECRET: str = config('CLIENT_SECRET')
    ROBLOX_TOKEN_URL: str = "https://apis.roblox.com/oauth/v1/token"
    ROBLOX_USERINFO_URL: str = "https://apis.roblox.com/oauth/v1/userinfo"
    PANEL_REDIRECT_URL: str = "http://localhost:5173/settings"

app = Flask(__name__)
settings = Settings()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

client = pymongo.MongoClient(
    settings.MONGO_URL,
    maxPoolSize=50,
    connectTimeoutMS=5000,
    serverSelectionTimeoutMS=5000
)
db = client[settings.DATABASE]
oauth_collection = db['oauth2']
pending_collection = db['pending_oauth2']

def handle_errors(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {str(e)}")
            return render_template('error.html', message="An error occurred. Please try again later."), 500
    return wrapper

def get_roblox_access_token(code: str) -> Optional[str]:
    """Get Roblox access token using authorization code."""
    try:
        response = requests.post(
            settings.ROBLOX_TOKEN_URL,
            data={
                "client_id": settings.CLIENT_ID,
                "client_secret": settings.CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )
        response.raise_for_status()
        return response.json().get('access_token')
    except (requests.RequestException, KeyError) as e:
        logger.error(f"Failed to get access token: {str(e)}")
        return None

def get_roblox_user_info(access_token: str) -> Optional[Tuple[int, str]]:
    """Get Roblox user info using access token."""
    try:
        response = requests.get(
            settings.ROBLOX_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        return int(data["sub"]), data["preferred_username"]
    except (requests.RequestException, KeyError) as e:
        logger.error(f"Failed to get user info: {str(e)}")
        return None

def update_user_verification(discord_id: int, roblox_id: int) -> None:
    """Update or insert user verification data."""
    update_data = {
        "roblox_id": roblox_id,
        "last_updated": int(time.time())
    }
    
    oauth_collection.update_one(
        {'discord_id': discord_id},
        {"$set": update_data},
        upsert=True
    )

@app.route('/auth')
@handle_errors
def auth():
    """Handle OAuth2 authorization callback."""
    code = request.args.get('code')
    panel = request.args.get("panel")
    discord_id = request.args.get('state')

    if not all([code, discord_id]):
        return 'Missing required parameters', 400

    try:
        discord_id = int(discord_id)
    except ValueError:
        return 'Invalid discord ID', 400

    logger.info(f'[VERIFICATION] {discord_id} attempting verification')

    if not pending_collection.find_one({'discord_id': discord_id}):
        return 'No active OAuth2 session found. Please contact ERM Support if this is incorrect.'

    access_token = get_roblox_access_token(code)
    if not access_token:
        return 'Failed to get access token', 500

    user_info = get_roblox_user_info(access_token)
    if not user_info:
        return 'Failed to get user info', 500

    roblox_id, username = user_info
    
    update_user_verification(discord_id, roblox_id)
    
    logger.info(f'[VERIFICATION] {discord_id} verified as {username}')

    if panel in [None, "", False, "false"]:
        return redirect(url_for('finished', username=username))
    return redirect(settings.PANEL_REDIRECT_URL)

@app.route('/finished')
@handle_errors
def finished():
    """Display verification completion page."""
    username = request.args.get('username')
    if not username:
        return redirect(url_for('auth'))
    return render_template('finished.html', username=username)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=False)
