from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import wraps
from typing import Optional, Tuple, TypeVar, Callable, Any, Dict
from urllib.parse import urljoin

from flask import Flask, Request, Response, request, redirect, url_for, render_template
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import pymongo
from pymongo.collection import Collection
from pymongo.database import Database as MongoDatabase
from pymongo.errors import PyMongoError
from decouple import config
import structlog

T = TypeVar('T')

class ErrorCode(Enum):
    """Standardized error codes for the application"""
    INVALID_REQUEST = "invalid_request"
    INVALID_SESSION = "invalid_session"
    TOKEN_ERROR = "token_error"
    USER_INFO_ERROR = "user_info_error"
    DATABASE_ERROR = "database_error"

@dataclass(frozen=True)
class Settings:
    """Application configuration with secure defaults and validation"""
    MONGO_URL: str = config('MONGO_URL')
    DATABASE: str = config('DATABASE')
    CLIENT_ID: str = config('CLIENT_ID')
    CLIENT_SECRET: str = config('CLIENT_SECRET')
    ROBLOX_BASE_URL: str = "https://apis.roblox.com"
    ROBLOX_TOKEN_PATH: str = "/oauth/v1/token"
    ROBLOX_USERINFO_PATH: str = "/oauth/v1/userinfo"
    PANEL_REDIRECT_URL: str = config('PANEL_REDIRECT_URL', default="http://localhost:5173/settings")
    REQUEST_TIMEOUT: int = config('REQUEST_TIMEOUT', default=10, cast=int)
    MONGO_MAX_POOL_SIZE: int = config('MONGO_MAX_POOL_SIZE', default=50, cast=int)
    MONGO_CONNECT_TIMEOUT_MS: int = config('MONGO_CONNECT_TIMEOUT_MS', default=5000, cast=int)
    MONGO_SERVER_SELECTION_TIMEOUT_MS: int = config('MONGO_SERVER_SELECTION_TIMEOUT_MS', default=3000, cast=int)
    RATE_LIMIT_WINDOW: int = config('RATE_LIMIT_WINDOW', default=60, cast=int)  # seconds
    RATE_LIMIT_MAX_REQUESTS: int = config('RATE_LIMIT_MAX_REQUESTS', default=100, cast=int)

    @property
    def ROBLOX_TOKEN_URL(self) -> str:
        return urljoin(self.ROBLOX_BASE_URL, self.ROBLOX_TOKEN_PATH)

    @property
    def ROBLOX_USERINFO_URL(self) -> str:
        return urljoin(self.ROBLOX_BASE_URL, self.ROBLOX_USERINFO_PATH)

@dataclass
class DatabaseClient:
    """Enhanced database client with proper connection handling and error management"""
    settings: Settings
    logger: structlog.BoundLogger
    _client: Optional[pymongo.MongoClient] = field(default=None, init=False)
    _db: Optional[MongoDatabase] = field(default=None, init=False)
    
    def __post_init__(self):
        self._initialize_connection()

    def _initialize_connection(self) -> None:
        """Initialize MongoDB connection with proper settings"""
        try:
            self._client = pymongo.MongoClient(
                self.settings.MONGO_URL,
                maxPoolSize=self.settings.MONGO_MAX_POOL_SIZE,
                connectTimeoutMS=self.settings.MONGO_CONNECT_TIMEOUT_MS,
                serverSelectionTimeoutMS=self.settings.MONGO_SERVER_SELECTION_TIMEOUT_MS,
                retryWrites=True,
                w='majority'
            )
            self._db = self._client[self.settings.DATABASE]
            # Verify connection
            self._client.admin.command('ping')
            self.logger.info("mongodb_connection_successful")
        except PyMongoError as e:
            self.logger.error("mongodb_connection_failed", error=str(e))
            raise

    @property
    def oauth_collection(self) -> Collection:
        return self._db['oauth2']

    @property
    def pending_collection(self) -> Collection:
        return self._db['pending_oauth2']

    def check_pending_verification(self, discord_id: int) -> bool:
        """Check if a discord ID has a pending verification"""
        try:
            result = self.pending_collection.find_one(
                {'discord_id': discord_id},
                projection={'_id': 1}
            )
            return result is not None
        except PyMongoError as e:
            self.logger.error("check_pending_verification_failed",
                            discord_id=discord_id,
                            error=str(e))
            raise

    def update_verification(self, discord_id: int, roblox_id: int) -> bool:
        """Update or create user verification record with proper error handling"""
        try:
            update_data = {
                'discord_id': discord_id,
                'roblox_id': roblox_id,
                'last_updated': datetime.utcnow()
            }
            result = self.oauth_collection.update_one(
                {'discord_id': discord_id},
                {'$set': update_data},
                upsert=True
            )
            self.logger.info("verification_updated",
                           discord_id=discord_id,
                           roblox_id=roblox_id,
                           modified_count=result.modified_count,
                           upserted_id=result.upserted_id)
            return True
        except PyMongoError as e:
            self.logger.error("update_verification_failed",
                            discord_id=discord_id,
                            roblox_id=roblox_id,
                            error=str(e))
            raise

class RobloxClient:
    """Enhanced Roblox API client with proper retry handling and logging"""
    def __init__(self, settings: Settings, logger: structlog.BoundLogger):
        self.settings = settings
        self.logger = logger
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create session with improved retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=5,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('https://', adapter)
        session.headers.update({
            'Accept': 'application/json',
            'User-Agent': 'OAuth2App/1.0'
        })
        return session

    def get_access_token(self, code: str) -> str:
        """Exchange authorization code for access token with proper error handling"""
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
            token_data = response.json()
            return token_data["access_token"]
        except requests.RequestException as e:
            self.logger.error("token_request_failed", error=str(e))
            raise

    def get_user_info(self, access_token: str) -> Tuple[int, str]:
        """Get user information with proper error handling"""
        try:
            response = self.session.get(
                self.settings.ROBLOX_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=self.settings.REQUEST_TIMEOUT
            )
            response.raise_for_status()
            user_data = response.json()
            return int(user_data["sub"]), user_data["preferred_username"]
        except requests.RequestException as e:
            self.logger.error("user_info_request_failed", error=str(e))
            raise

def create_error_response(error: ErrorCode, message: str, status_code: int = 400) -> Response:
    """Create standardized error response"""
    return Response(
        response=message,
        status=status_code,
        mimetype='application/json'
    )

def handle_errors(f: Callable[..., T]) -> Callable[..., T]:
    """Decorator for standardized error handling"""
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> T:
        try:
            return f(*args, **kwargs)
        except requests.RequestException as e:
            return create_error_response(
                ErrorCode.TOKEN_ERROR,
                f"External API error: {str(e)}",
                status_code=502
            )
        except PyMongoError as e:
            return create_error_response(
                ErrorCode.DATABASE_ERROR,
                f"Database error: {str(e)}",
                status_code=503
            )
        except Exception as e:
            return create_error_response(
                ErrorCode.INVALID_REQUEST,
                f"Internal server error: {str(e)}",
                status_code=500
            )
    return decorated_function

class OAuth2App:
    """Enhanced OAuth2 application with improved structure and error handling"""
    def __init__(self):
        self.logger = structlog.get_logger()
        self.settings = Settings()
        self.db = DatabaseClient(self.settings, self.logger)
        self.roblox_client = RobloxClient(self.settings, self.logger)
        self.app = self._create_app()

    def _create_app(self) -> Flask:
        """Create and configure Flask application"""
        app = Flask(__name__)
        app.url_map.strict_slashes = False
        
        # Register routes
        app.add_url_rule('/auth', 'auth', self._handle_auth, methods=['GET'])
        app.add_url_rule('/finished', 'finished', self._handle_finished, methods=['GET'])
        
        return app

    def _validate_auth_request(self, request: Request) -> Tuple[str, int]:
        """Validate authentication request parameters"""
        code = request.args.get('code')
        discord_id = request.args.get('state')
        
        if not code or not discord_id:
            raise ValueError("Missing required parameters")
        
        try:
            discord_id_int = int(discord_id)
        except ValueError:
            raise ValueError("Invalid discord_id format")
            
        return code, discord_id_int

    @handle_errors
    def _handle_auth(self) -> Response:
        """Handle OAuth2 authorization callback with improved error handling"""
        # Validate request
        code, discord_id = self._validate_auth_request(request)
        panel = request.args.get("panel", "").lower() in ('true', '1', 't')
        
        self.logger.info("verification_attempt", discord_id=discord_id)

        # Check pending verification
        if not self.db.check_pending_verification(discord_id):
            return create_error_response(
                ErrorCode.INVALID_SESSION,
                "No active OAuth2 session found"
            )

        # Get access token and user info
        access_token = self.roblox_client.get_access_token(code)
        roblox_id, username = self.roblox_client.get_user_info(access_token)
        
        # Update verification status
        self.db.update_verification(discord_id, roblox_id)
        
        self.logger.info("verification_successful",
                        discord_id=discord_id,
                        roblox_username=username)

        # Handle redirect
        redirect_url = (self.settings.PANEL_REDIRECT_URL if panel
                       else url_for('finished', username=username))
        return redirect(redirect_url)

    @handle_errors
    def _handle_finished(self) -> Response:
        """Handle verification completion page"""
        username = request.args.get('username')
        if not username:
            return redirect(url_for('auth'))
        return render_template('finished.html', username=username)

    def run(self, host: str = "0.0.0.0", port: int = 80, debug: bool = False) -> None:
        """Run the Flask application"""
        self.app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    oauth_app = OAuth2App()
    oauth_app.run()
