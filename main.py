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
import secrets
from werkzeug.middleware.proxy_fix import ProxyFix

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
    PANEL_REDIRECT_URL: str = config('PANEL_REDIRECT_URL', default="http://localhost:5173/settings")
    REQUEST_TIMEOUT: int = config('REQUEST_TIMEOUT', default=10)
    FLASK_SECRET_KEY: str = config('FLASK_SECRET_KEY', default=secrets.token_hex(32))
    SSL_CERT_PATH: Optional[str] = config('SSL_CERT_PATH', default=None)
    SSL_KEY_PATH: Optional[str] = config('SSL_KEY_PATH', default=None)

# region Security Middleware
def security_headers():
    """Add security headers to all responses"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            response = f(*args, **kwargs)
            if isinstance(response, Response):
                response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
                response.headers['X-Content-Type-Options'] = 'nosniff'
                response.headers['X-Frame-Options'] = 'DENY'
                response.headers['X-XSS-Protection'] = '1; mode=block'
                response.headers['Content-Security-Policy'] = "default-src 'self'"
            return response
        return decorated_function
    return decorator

# region Web Application
class OAuth2App:
    """Main OAuth2 application handler"""
    def __init__(self):
        self.app = Flask(__name__)
        self._setup_logging()
        self.settings = Settings()
        self._configure_app()
        self.db = Database(self.settings, self.logger)
        self.roblox_client = RobloxClient(self.settings, self.logger)
        self._setup_routes()
    
    def _configure_app(self) -> None:
        """Configure Flask application settings and middleware"""
        self.app.config['SECRET_KEY'] = self.settings.FLASK_SECRET_KEY
        self.app.config['SESSION_COOKIE_SECURE'] = True
        self.app.config['SESSION_COOKIE_HTTPONLY'] = True
        self.app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        self.app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
        
        # Support for reverse proxies
        self.app.wsgi_app = ProxyFix(
            self.app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
        )

    def _setup_logging(self) -> None:
        """Configure application logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s [%(name)s] %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('oauth2.log')
            ]
        )
        self.logger = logging.getLogger('oauth2')

    def _setup_routes(self) -> None:
        """Configure application routes with security headers"""
        self.app.before_request(self._validate_request)
        
        self.app.add_url_rule('/auth', 'auth', 
                             security_headers()(self._handle_auth), 
                             methods=['GET'])
        self.app.add_url_rule('/finished', 'finished', 
                             security_headers()(self._handle_finished), 
                             methods=['GET'])

    def _validate_request(self):
        """Validate incoming requests"""
        if not request.is_secure and not self.app.debug:
            return self.error_response('HTTPS required', 403)

        return None

    def run(self, host: str = "0.0.0.0", port: int = 443):
        """Run the Flask application in production mode"""
        ssl_context = None
        if self.settings.SSL_CERT_PATH and self.settings.SSL_KEY_PATH:
            ssl_context = (self.settings.SSL_CERT_PATH, self.settings.SSL_KEY_PATH)
        
        from waitress import serve
        if ssl_context:
            # Use waitress with SSL
            serve(self.app, host=host, port=port, 
                  url_scheme='https',
                  ssl_context=ssl_context)
        else:
            serve(self.app, host=host, port=port)

# Application entry point
if __name__ == '__main__':
    oauth_app = OAuth2App()
    oauth_app.run()
