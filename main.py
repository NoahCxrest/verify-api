from flask import Flask, request, redirect, url_for, render_template, Response
import requests
import pymongo
from decouple import config
import time
import logging
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any
from functools import wraps, lru_cache
from contextlib import contextmanager
import threading
from datetime import datetime, timedelta
import asyncio
from concurrent.futures import ThreadPoolExecutor
from cachetools import TTLCache, cached
from pymongo.errors import PyMongoError
import traceback

@dataclass(frozen=True)
class Settings:
    """Immutable application settings"""
    MONGO_URL: str = config('MONGO_URL')
    DATABASE: str = config('DATABASE')
    CLIENT_ID: int = config('CLIENT_ID')
    CLIENT_SECRET: str = config('CLIENT_SECRET')
    ROBLOX_TOKEN_URL: str = "https://apis.roblox.com/oauth/v1/token"
    ROBLOX_USERINFO_URL: str = "https://apis.roblox.com/oauth/v1/userinfo"
    PANEL_REDIRECT_URL: str = "http://localhost:5173/settings"
    CACHE_TTL: int = 3600  # 1 hour
    MAX_RETRIES: int = 3
    TIMEOUT: int = 10
    POOL_SIZE: int = 100
    REQUEST_TIMEOUT: int = 5

class AppState:
    """Global application state"""
    def __init__(self):
        self.settings = Settings()
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RobloxOAuth2/1.0',
            'Accept': 'application/json'
        })
        self.cache = TTLCache(maxsize=1000, ttl=self.settings.CACHE_TTL)
        self._setup_logging()
        self._setup_mongodb()

    def _setup_logging(self) -> None:
        """Configure application logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s [%(name)s] %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('oauth.log')
            ]
        )
        self.logger = logging.getLogger('oauth2')

    def _setup_mongodb(self) -> None:
        """Initialize MongoDB connection with optimized settings"""
        self.mongo_client = pymongo.MongoClient(
            self.settings.MONGO_URL,
            maxPoolSize=self.settings.POOL_SIZE,
            minPoolSize=10,
            maxIdleTimeMS=45000,
            connectTimeoutMS=2000,
            serverSelectionTimeoutMS=3000,
            socketTimeoutMS=5000,
            waitQueueMultiple=10
        )
        self.db = self.mongo_client[self.settings.DATABASE]
        self.oauth_collection = self.db['oauth2']
        self.pending_collection = self.db['pending_oauth2']
        
        # Create indexes
        self.oauth_collection.create_index('discord_id', unique=True)
        self.pending_collection.create_index('discord_id', unique=True)
        self.pending_collection.create_index('created_at', expireAfterSeconds=3600)
# endregion

# region Database Operations
class DatabaseOperations:
    """Encapsulated database operations with retry mechanism"""
    def __init__(self, state: AppState):
        self.state = state
        
    @contextmanager
    def error_handling(self, operation: str):
        try:
            yield
        except PyMongoError as e:
            self.state.logger.error(f"Database error during {operation}: {str(e)}")
            raise

    def check_pending_verification(self, discord_id: int) -> bool:
        with self.error_handling("pending verification check"):
            return bool(self.state.pending_collection.find_one(
                {'discord_id': discord_id},
                projection={'_id': 1}
            ))

    def update_verification(self, discord_id: int, roblox_id: int) -> None:
        with self.error_handling("verification update"):
            update_data = {
                "discord_id": discord_id,
                "roblox_id": roblox_id,
                "last_updated": int(time.time())
            }
            self.state.oauth_collection.update_one(
                {'discord_id': discord_id},
                {'$set': update_data},
                upsert=True
            )
# endregion

# region Roblox API Client
class RobloxClient:
    """Handles Roblox API interactions with caching and retry logic"""
    def __init__(self, state: AppState):
        self.state = state

    @cached(cache=TTLCache(maxsize=100, ttl=300))  # 5-minute cache
    async def get_access_token(self, code: str) -> Optional[str]:
        """Get Roblox access token with caching"""
        for attempt in range(self.state.settings.MAX_RETRIES):
            try:
                response = await self.state.thread_pool.submit(
                    self.state.session.post,
                    self.state.settings.ROBLOX_TOKEN_URL,
                    data={
                        "client_id": self.state.settings.CLIENT_ID,
                        "client_secret": self.state.settings.CLIENT_SECRET,
                        "grant_type": "authorization_code",
                        "code": code
                    },
                    timeout=self.state.settings.REQUEST_TIMEOUT
                )
                response.raise_for_status()
                return response.json().get('access_token')
            except Exception as e:
                if attempt == self.state.settings.MAX_RETRIES - 1:
                    self.state.logger.error(f"Failed to get access token after {attempt + 1} attempts: {str(e)}")
                    return None
                await asyncio.sleep(1)

    @cached(cache=TTLCache(maxsize=1000, ttl=3600))  # 1-hour cache
    async def get_user_info(self, access_token: str) -> Optional[Tuple[int, str]]:
        """Get Roblox user info with caching"""
        try:
            response = await self.state.thread_pool.submit(
                self.state.session.get,
                self.state.settings.ROBLOX_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=self.state.settings.REQUEST_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
            return int(data["sub"]), data["preferred_username"]
        except Exception as e:
            self.state.logger.error(f"Failed to get user info: {str(e)}")
            return None
# endregion

# region Flask Application
class OAuth2App:
    """Main application class"""
    def __init__(self):
        self.app = Flask(__name__)
        self.state = AppState()
        self.db_ops = DatabaseOperations(self.state)
        self.roblox_client = RobloxClient(self.state)
        self._setup_routes()

    def error_response(self, message: str, status_code: int = 400) -> Response:
        """Standardized error response"""
        return Response(
            response=message,
            status=status_code,
            mimetype='text/plain'
        )

    def _setup_routes(self) -> None:
        """Configure Flask routes"""
        self.app.add_url_rule('/auth', 'auth', self.handle_auth, methods=['GET'])
        self.app.add_url_rule('/finished', 'finished', self.handle_finished, methods=['GET'])

    async def handle_auth(self):
        """Handle OAuth2 authorization callback"""
        code = request.args.get('code')
        panel = request.args.get("panel")
        discord_id = request.args.get('state')

        if not all([code, discord_id]):
            return self.error_response('Missing required parameters')

        try:
            discord_id = int(discord_id)
        except ValueError:
            return self.error_response('Invalid discord ID')

        self.state.logger.info(f'[VERIFICATION] {discord_id} attempting verification')

        if not self.db_ops.check_pending_verification(discord_id):
            return self.error_response('No active OAuth2 session found')

        access_token = await self.roblox_client.get_access_token(code)
        if not access_token:
            return self.error_response('Failed to get access token', 500)

        user_info = await self.roblox_client.get_user_info(access_token)
        if not user_info:
            return self.error_response('Failed to get user info', 500)

        roblox_id, username = user_info
        self.db_ops.update_verification(discord_id, roblox_id)
        
        self.state.logger.info(f'[VERIFICATION] {discord_id} verified as {username}')

        return redirect(
            url_for('finished', username=username) 
            if panel in [None, "", False, "false"] 
            else self.state.settings.PANEL_REDIRECT_URL
        )

    def handle_finished(self):
        """Display verification completion page"""
        username = request.args.get('username')
        if not username:
            return redirect(url_for('auth'))
        return render_template('finished.html', username=username)

    def run(self, host: str = "0.0.0.0", port: int = 80, debug: bool = False):
        """Run the Flask application"""
        self.app.run(host=host, port=port, debug=debug)
# endregion

if __name__ == '__main__':
    oauth_app = OAuth2App()
    oauth_app.run()
