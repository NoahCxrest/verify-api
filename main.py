from flask import Flask, request, redirect, url_for, render_template, Response
import requests
import pymongo
from decouple import config
import time
import logging
from dataclasses import dataclass
from typing import Optional, Tuple
from pymongo.errors import DuplicateKeyError, OperationFailure
from functools import wraps
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# region Configuration
@dataclass(frozen=True)
class Settings:
    """Application configuration settings"""
    MONGO_URL: str = config('MONGO_URL')
    DATABASE: str = config('DATABASE')
    CLIENT_ID: str = config('CLIENT_ID')
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
        self.client = pymongo.MongoClient(
            settings.MONGO_URL,
            maxPoolSize=50,
            connectTimeoutMS=5000,
            serverSelectionTimeoutMS=3000
        )
        self.db = self.client[settings.DATABASE]
        self.oauth_collection = self.db['oauth2']
        self.pending_collection = self.db['pending_oauth2']
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        """Ensure indexes exist, handling existing indexes gracefully"""
        index_fields = [
            ('oauth_collection', 'discord_id'),
            ('pending_collection', 'discord_id')
        ]
        for collection_name, field in index_fields:
            self._create_index_if_not_exists(collection_name, field)

    def _create_index_if_not_exists(self, collection_name: str, field: str) -> None:
        """Create unique index if it doesn't exist"""
        collection = getattr(self, collection_name)
        try:
            if field not in {index['name'] for index in collection.list_indexes()}:
                collection.create_index([(field, pymongo.ASCENDING)], unique=True, background=True)
        except OperationFailure as e:
            self.logger.warning(f"Index creation warning for {collection_name}: {e}")

    def check_pending_verification(self, discord_id: int) -> bool:
        """Check if a discord ID has a pending verification"""
        return self._get_pending_record(discord_id) is not None

    def _get_pending_record(self, discord_id: int):
        """Fetch pending record for discord ID"""
        try:
            return self.pending_collection.find_one({'discord_id': discord_id}, projection={'_id': 1})
        except Exception as e:
            self.logger.error(f"Error checking pending verification for {discord_id}: {e}")
            return None

    def update_verification(self, discord_id: int, roblox_id: int) -> bool:
        """Update or create user verification record"""
        update_data = {
            'roblox_id': roblox_id,
            'last_updated': int(time.time())
        }
        try:
            # Use upsert to combine update and insert into one call
            self.oauth_collection.update_one(
                {'discord_id': discord_id},
                {'$set': update_data},
                upsert=True
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to update verification for {discord_id}: {e}")
            return False
# endregion

# region Roblox API Client
class RobloxClient:
    """Handles all Roblox API interactions"""
    def __init__(self, settings: Settings, logger: logging.Logger):
        self.settings = settings
        self.logger = logger
        self.session = self._create_session()

    def _create_session(self):
        """Create session with retries and timeout"""
        session = requests.Session()
        retry = Retry(
            total=5, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('https://', adapter)
        session.headers.update({'Accept': 'application/json'})
        return session

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
            self.logger.error(f"Failed to get access token: {e}")
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
            self.logger.error(f"Failed to get user info: {e}")
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
        return Response(response=message, status=status_code, mimetype='text/plain')

    def _validate_auth_request(self, code: str, discord_id: str) -> Optional[Tuple[str, int]]:
        """Validate authentication request parameters"""
        try:
            discord_id_int = int(discord_id)
            return code, discord_id_int if code and discord_id else None
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
        return redirect(url_for('auth')) if not username else render_template('finished.html', username=username)

    def run(self, host: str = "0.0.0.0", port: int = 80, debug: bool = False):
        """Run the Flask application"""
        self.app.run(host=host, port=port, debug=debug)
# endregion

# Application entry point
if __name__ == '__main__':
    oauth_app = OAuth2App()
    oauth_app.run()
