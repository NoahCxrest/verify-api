from flask import Flask, request, redirect, url_for, render_template, jsonify
from functools import wraps
import requests
import pymongo
from decouple import config
import time
from typing import Optional, Dict, Any
import logging
from dataclasses import dataclass
from http import HTTPStatus

@dataclass
class AppConfig:
    MONGO_URL: str
    DATABASE: str
    CLIENT_ID: int
    CLIENT_SECRET: str
    ROBLOX_OAUTH_TOKEN_URL: str = "https://apis.roblox.com/oauth/v1/token"
    ROBLOX_USERINFO_URL: str = "https://apis.roblox.com/oauth/v1/userinfo"
    PANEL_REDIRECT_URL: str = "http://localhost:5173/settings"
    HOST: str = "0.0.0.0"
    PORT: int = 80
    DEBUG: bool = False

class DatabaseClient:
    def __init__(self, config: AppConfig):
        self.client = pymongo.MongoClient(config.MONGO_URL)
        self.db = self.client[config.DATABASE]
        self.oauth_collection = self.db['oauth2']
        self.pending_collection = self.db['pending_oauth2']

    def get_pending_verification(self, discord_id: int) -> Optional[Dict]:
        return self.pending_collection.find_one({'discord_id': discord_id})

    def update_or_create_verification(self, discord_id: int, roblox_id: int) -> None:
        update_data = {
            "roblox_id": roblox_id,
            "last_updated": int(time.time())
        }

        if self.oauth_collection.find_one({"discord_id": discord_id}):
            self.oauth_collection.update_one(
                {'discord_id': discord_id},
                {"$set": update_data}
            )
        else:
            self.oauth_collection.insert_one({
                "discord_id": discord_id,
                **update_data
            })

class RobloxOAuth:
    def __init__(self, config: AppConfig):
        self.config = config

    def get_access_token(self, code: str) -> str:
        response = requests.post(
            self.config.ROBLOX_OAUTH_TOKEN_URL,
            data={
                "client_id": self.config.CLIENT_ID,
                "client_secret": self.config.CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        response.raise_for_status()
        return response.json()['access_token']

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        response = requests.get(
            self.config.ROBLOX_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        response.raise_for_status()
        return response.json()

def create_app(config: AppConfig) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config)

    db_client = DatabaseClient(config)
    roblox_oauth = RobloxOAuth(config)

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    def handle_errors(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except requests.exceptions.RequestException as e:
                logger.error(f"OAuth request failed: {str(e)}")
                return jsonify({"error": "Failed to communicate with Roblox API"}), HTTPStatus.BAD_GATEWAY
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")
                return jsonify({"error": "Internal server error"}), HTTPStatus.INTERNAL_SERVER_ERROR
        return decorated_function

    @app.route('/auth')
    @handle_errors
    def auth():
        code = request.args.get('code')
        panel = request.args.get("panel")
        discord_id = request.args.get('state')

        if not all([code, discord_id]):
            return jsonify({"error": "Missing required parameters"}), HTTPStatus.BAD_REQUEST

        try:
            discord_id = int(discord_id)
        except ValueError:
            return jsonify({"error": "Invalid discord_id format"}), HTTPStatus.BAD_REQUEST

        logger.info(f'Verification attempt from Discord ID: {discord_id}')

        if not db_client.get_pending_verification(discord_id):
            return jsonify({
                "error": "No active OAuth2 session found. Please contact ERM Support if this is incorrect."
            }), HTTPStatus.NOT_FOUND

        access_token = roblox_oauth.get_access_token(code)
        user_info = roblox_oauth.get_user_info(access_token)
        
        db_client.update_or_create_verification(discord_id, int(user_info["sub"]))
        
        logger.info(f'Successfully verified Discord ID {discord_id} as {user_info["preferred_username"]}')

        if panel and panel.lower() not in ['none', '', 'false']:
            return redirect(config.PANEL_REDIRECT_URL)
        return redirect(url_for('finished', username=user_info['preferred_username']))

    @app.route('/finished')
    @handle_errors
    def finished():
        username = request.args.get('username')
        if not username:
            return jsonify({"error": "Missing username parameter"}), HTTPStatus.BAD_REQUEST
        return render_template('finished.html', username=username)

    return app

def main():
    config = AppConfig(
        MONGO_URL=config('MONGO_URL'),
        DATABASE=config('DATABASE'),
        CLIENT_ID=int(config('CLIENT_ID')),
        CLIENT_SECRET=config('CLIENT_SECRET')
    )
    
    app = create_app(config)
    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG
    )

if __name__ == '__main__':
    main()
