from flask import Flask, request, redirect, url_for, render_template, Response
import requests
import pymongo
from decouple import config
import time
import logging
from dataclasses import dataclass
from typing import Optional, Tuple
from functools import wraps
from pymongo.errors import DuplicateKeyError, OperationFailure

# region Configuration
@dataclass(frozen=True)
class Settings:
    """Application configuration settings"""
    MONGO_URL: str = config('MONGO_URL')
    DATABASE: str = config('DATABASE')
    CLIENT_ID: int = config('CLIENT_ID')
    CLIENT_SECRET: str = config('CLIENT_SECRET')
    ROBLOX_TOKEN_URL: str = "https://apis.roblox.com/oauth/v1/token"
    ROBLOX_USERINFO_URL: str = "https://apis.roblox.com/oauth/v1/userinfo"
    PANEL_REDIRECT_URL: str = "http://localhost:5173/settings"
    REQUEST_TIMEOUT: int = 10
# endregion

# region Database
class Database:
    """Database connection and operations handler"""
    def __init__(self, settings: Settings, logger: logging.Logger):
        self.logger = logger
        self._init_connection(settings)
        self._ensure_indexes()
    
    def _init_connection(self, settings: Settings) -> None:
        """Initialize MongoDB connection"""
        self.client = pymongo.MongoClient(
            settings.MONGO_URL,
            maxPoolSize=50,
            connectTimeoutMS=5000,
            serverSelectionTimeoutMS=3000
        )
        self.db = self.client[settings.DATABASE]
        self.oauth_collection = self.db['oauth2']
        self.pending_collection = self.db['pending_oauth2']
    
    def _ensure_indexes(self) -> None:
        """Ensure indexes exist, handling existing indexes gracefully"""
        try:
            existing_indexes = set(index['name'] for index in self.oauth_collection.list_indexes())
            
            if 'discord_id_1' not in existing_indexes:
                self.oauth_collection.create_index('discord_id', unique=True, background=True)
            if 'discord_id_1' not in set(index['name'] for index in self.pending_collection.list_indexes()):
                self.pending_collection.create_index('discord_id', unique=True, background=True)
                
        except OperationFailure as e:
            self.logger.warning(f"Index creation warning: {str(e)}")
            pass
        except Exception as e:
            self.logger.error(f"Failed to ensure indexes: {str(e)}")
            raise
    
    def check_pending_verification(self, discord_id: int) -> bool:
        """Check if a discord ID has a pending verification"""
        try:
            return bool(self.pending_collection.find_one(
                {'discord_id': discord_id},
                projection={'_id': 1}
            ))
        except Exception as e:
            self.logger.error(f"Error checking pending verification: {str(e)}")
            return False
    
    def update_verification(self, discord_id: int, roblox_id: int) -> bool:
        """Update or create user verification record"""
        try:
            update_data = {
                'roblox_id': roblox_id,
                'last_updated': int(time.time())
            }
            
            # Try to update existing record first
            result = self.oauth_collection.update_one(
                {'discord_id': discord_id},
                {'$set': update_data}
            )
            
            # If no existing record was found, insert new one
            if result.matched_count == 0:
                try:
                    self.oauth_collection.insert_one({
                        'discord_id': discord_id,
                        **update_data
                    })
                except DuplicateKeyError:
                    # If insert fails due to race condition, try update again
                    self.oauth_collection.update_one(
                        {'discord_id': discord_id},
                        {'$set': update_data}
                    )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update verification: {str(e)}")
            return False
# endregion

# region Roblox API Client
class RobloxClient:
    """Handles all Roblox API interactions"""
    def __init__(self, settings: Settings, logger: logging.Logger):
        self.settings = settings
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({'Accept': 'application/json'})
    
    def get_access_token(self, code: str) -> Optional[str]:
        """Exchange authorization code for access token"""
        try:
            response = self.session.post(
                self.settings.ROBLOX_TOKEN_URL,
                data={
                    "client_id": self.settings.CLIENT_ID,
                    "client_secret": self.settings.CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code
                },
                timeout=self.settings.REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return response.json().get('access_token')
        except Exception as e:
            self.logger.error(f"Failed to get access token: {str(e)}")
            return None

    def get_user_info(self, access_token: str) -> Optional[Tuple[int, str]]:
        """Get user information using access token"""
        try:
            response = self.session.get(
                self.settings.ROBLOX_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=self.settings.REQUEST_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
            return int(data["sub"]), data["preferred_username"]
        except Exception as e:
            self.logger.error(f"Failed to get user info: {str(e)}")
            return None
# endregion

# region Web Application
class OAuth2App:
    """Main OAuth2 application handler"""
    def __init__(self):
        self.app = Flask(__name__)
        self._setup_logging()
        self.settings = Settings()
        self.db = Database(self.settings, self.logger)
        self.roblox_client = RobloxClient(self.settings, self.logger)
        self._setup_routes()
    
    def _setup_logging(self) -> None:
        """Configure application logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s [%(name)s] %(message)s'
        )
        self.logger = logging.getLogger('oauth2')

    def _setup_routes(self) -> None:
        """Configure application routes"""
        self.app.add_url_rule('/auth', 'auth', self._handle_auth, methods=['GET'])
        self.app.add_url_rule('/finished', 'finished', self._handle_finished, methods=['GET'])

    def error_response(self, message: str, status_code: int = 400) -> Response:
        """Create standardized error response"""
        return Response(
            response=message,
            status=status_code,
            mimetype='text/plain'
        )

    def _validate_auth_request(self, code: str, discord_id: str) -> Optional[Tuple[str, int]]:
        """Validate authentication request parameters"""
        if not all([code, discord_id]):
            return None
        
        try:
            discord_id_int = int(discord_id)
            return code, discord_id_int
        except ValueError:
            return None

    def _handle_auth(self):
        """Handle OAuth2 authorization callback"""
        code = request.args.get('code')
        panel = request.args.get("panel")
        discord_id = request.args.get('state')

        validation_result = self._validate_auth_request(code, discord_id)
        if validation_result is None:
            return self.error_response('Invalid request parameters')
        
        code, discord_id = validation_result
        self.logger.info(f'[VERIFICATION] {discord_id} attempting verification')

        if not self.db.check_pending_verification(discord_id):
            return self.error_response('No active OAuth2 session found')

        access_token = self.roblox_client.get_access_token(code)
        if not access_token:
            return self.error_response('Failed to get access token', 500)

        user_info = self.roblox_client.get_user_info(access_token)
        if not user_info:
            return self.error_response('Failed to get user info', 500)

        roblox_id, username = user_info
        
        if not self.db.update_verification(discord_id, roblox_id):
            return self.error_response('Failed to update verification status', 500)

        self.logger.info(f'[VERIFICATION] {discord_id} verified as {username}')

        return redirect(
            url_for('finished', username=username)
            if panel in [None, "", False, "false"]
            else self.settings.PANEL_REDIRECT_URL
        )

    def _handle_finished(self):
        """Handle verification completion page"""
        username = request.args.get('username')
        if not username:
            return redirect(url_for('auth'))
        return render_template('finished.html', username=username)

    def run(self, host: str = "0.0.0.0", port: int = 80, debug: bool = False):
        """Run the Flask application"""
        self.app.run(host=host, port=port, debug=debug)
# endregion

# Application entry point
if __name__ == '__main__':
    oauth_app = OAuth2App()
    oauth_app.run()
