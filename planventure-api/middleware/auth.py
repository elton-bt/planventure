"""
Authentication Middleware for PlanVenture API
Provides JWT authentication, rate limiting, and request validation
"""
from functools import wraps
from flask import request, jsonify, current_app, g
from datetime import datetime, timezone, timedelta
import time
from collections import defaultdict
import ipaddress
import jwt

# Optional Redis import
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    REDIS_AVAILABLE = False

# Local imports
from models.user import User, JWTUtils

class AuthenticationError(Exception):
    """Custom exception for authentication errors"""
    def __init__(self, message, status_code=401):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class RateLimitError(Exception):
    """Custom exception for rate limiting errors"""
    def __init__(self, message, status_code=429):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class AuthMiddleware:
    """
    Authentication middleware class for protecting routes
    """
    
    def __init__(self, app=None):
        self.app = app
        self.rate_limit_storage = defaultdict(list)
        self.redis_client = None
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize middleware with Flask app"""
        self.app = app
        
        # Try to initialize Redis for rate limiting only if available
        if REDIS_AVAILABLE:
            try:
                redis_url = app.config.get('REDIS_URL', 'redis://localhost:6379/0')
                self.redis_client = redis.from_url(redis_url)
                self.redis_client.ping()  # Test connection
                app.logger.info("Redis connected for rate limiting")
            except Exception as e:
                app.logger.warning(f"Redis not available, using in-memory rate limiting: {str(e)}")
                self.redis_client = None
        else:
            app.logger.info("Redis module not installed, using in-memory rate limiting")
            self.redis_client = None
        
        # Register error handlers
        @app.errorhandler(AuthenticationError)
        def handle_auth_error(error):
            return jsonify({
                'success': False,
                'error': error.message,
                'type': 'authentication_error'
            }), error.status_code
        
        @app.errorhandler(RateLimitError)
        def handle_rate_limit_error(error):
            return jsonify({
                'success': False,
                'error': error.message,
                'type': 'rate_limit_error'
            }), error.status_code
    
    def get_client_ip(self, request):
        """Get client IP address considering proxies"""
        # Check for forwarded IP addresses
        forwarded_ips = request.headers.getlist("X-Forwarded-For")
        if forwarded_ips:
            # Take the first IP from the list
            client_ip = forwarded_ips[0].split(',')[0].strip()
        else:
            client_ip = request.headers.get('X-Real-IP') or request.remote_addr
        
        return client_ip
    
    def is_rate_limited(self, identifier, max_requests=100, window_minutes=15):
        """
        Check if request should be rate limited
        
        Args:
            identifier (str): Unique identifier (IP, user_id, etc.)
            max_requests (int): Maximum requests allowed
            window_minutes (int): Time window in minutes
        
        Returns:
            bool: True if rate limited, False otherwise
        """
        now = time.time()
        window_start = now - (window_minutes * 60)
        
        if self.redis_client and REDIS_AVAILABLE:
            try:
                # Use Redis for distributed rate limiting
                pipe = self.redis_client.pipeline()
                key = f"rate_limit:{identifier}"
                
                # Remove old entries
                pipe.zremrangebyscore(key, 0, window_start)
                # Count current requests
                pipe.zcard(key)
                # Add current request
                pipe.zadd(key, {str(now): now})
                # Set expiration
                pipe.expire(key, window_minutes * 60)
                
                results = pipe.execute()
                current_requests = results[1]
                
                return current_requests >= max_requests
                
            except Exception as e:
                current_app.logger.error(f"Redis rate limiting error: {str(e)}")
                # Fallback to in-memory
        
        # In-memory rate limiting
        requests = self.rate_limit_storage[identifier]
        
        # Remove old requests
        self.rate_limit_storage[identifier] = [
            req_time for req_time in requests 
            if req_time > window_start
        ]
        
        # Check if limit exceeded
        if len(self.rate_limit_storage[identifier]) >= max_requests:
            return True
        
        # Add current request
        self.rate_limit_storage[identifier].append(now)
        return False
    
    def extract_token_from_request(self, request):
        """
        Extract JWT token from request headers
        
        Args:
            request: Flask request object
            
        Returns:
            str: JWT token or None
        """
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None
        
        try:
            # Extract token from "Bearer <token>"
            token_type, token = auth_header.split(' ', 1)
            if token_type.lower() != 'bearer':
                raise ValueError("Invalid token type")
            return token.strip()
        except ValueError:
            return None
    
    def validate_token(self, token):
        """
        Validate JWT token and return user
        
        Args:
            token (str): JWT token
            
        Returns:
            User: User object if valid
            
        Raises:
            AuthenticationError: If token is invalid
        """
        if not token:
            raise AuthenticationError("Authentication token is required")
        
        try:
            # Verify token using JWTUtils
            payload = JWTUtils.verify_token(token, 'access')
            if not payload:
                raise AuthenticationError("Invalid or expired token")
            
            # Get user from token
            user = User.get_user_from_token(token)
            if not user:
                raise AuthenticationError("User not found or inactive")
            
            # Additional security checks
            if not user.is_active:
                raise AuthenticationError("Account is deactivated")
            
            if user.is_account_locked():
                raise AuthenticationError("Account is temporarily locked")
            
            return user
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid token")
        except Exception as e:
            current_app.logger.error(f"Token validation error: {str(e)}")
            raise AuthenticationError("Token validation failed")
    
    def check_permissions(self, user, required_permissions=None):
        """
        Check if user has required permissions
        
        Args:
            user: User object
            required_permissions: List of required permissions
            
        Returns:
            bool: True if authorized
        """
        # For now, just check if user is active and verified
        # You can extend this for role-based permissions
        
        if required_permissions is None:
            return True
        
        # Example permission checks (extend as needed)
        user_permissions = []
        
        if user.is_verified:
            user_permissions.append('verified')
        
        if user.is_active:
            user_permissions.append('active')
        
        # Check if user has all required permissions
        return all(perm in user_permissions for perm in required_permissions)

# Global middleware instance
auth_middleware = AuthMiddleware()

def jwt_required(optional=False, permissions=None, rate_limit=None):
    """
    Decorator to require JWT authentication
    
    Args:
        optional (bool): If True, authentication is optional
        permissions (list): Required permissions
        rate_limit (dict): Rate limiting config {'max_requests': 100, 'window_minutes': 15}
    
    Usage:
        @jwt_required()
        @jwt_required(optional=True)
        @jwt_required(permissions=['verified'])
        @jwt_required(rate_limit={'max_requests': 10, 'window_minutes': 1})
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                # Rate limiting check
                if rate_limit:
                    client_ip = auth_middleware.get_client_ip(request)
                    max_req = rate_limit.get('max_requests', 100)
                    window = rate_limit.get('window_minutes', 15)
                    
                    if auth_middleware.is_rate_limited(
                        f"ip:{client_ip}", 
                        max_req, 
                        window
                    ):
                        raise RateLimitError(
                            f"Rate limit exceeded. Maximum {max_req} requests per {window} minutes."
                        )
                
                # Extract token
                token = auth_middleware.extract_token_from_request(request)
                
                if not token:
                    if optional:
                        # No token provided but it's optional
                        g.current_user = None
                        return f(*args, **kwargs)
                    else:
                        raise AuthenticationError("Authorization header is missing")
                
                # Validate token and get user
                user = auth_middleware.validate_token(token)
                
                # Check permissions
                if permissions and not auth_middleware.check_permissions(user, permissions):
                    raise AuthenticationError("Insufficient permissions", 403)
                
                # User-based rate limiting (more restrictive for authenticated users)
                if rate_limit and user:
                    user_max_req = rate_limit.get('max_requests', 100) * 2  # Authenticated users get more requests
                    user_window = rate_limit.get('window_minutes', 15)
                    
                    if auth_middleware.is_rate_limited(
                        f"user:{user.id}", 
                        user_max_req, 
                        user_window
                    ):
                        raise RateLimitError(
                            f"User rate limit exceeded. Maximum {user_max_req} requests per {user_window} minutes."
                        )
                
                # Store user in Flask's g object for access in the route
                g.current_user = user
                
                # Log successful authentication
                current_app.logger.info(f"Authenticated user: {user.email}")
                
                # Call the protected function with user as first argument
                return f(user, *args, **kwargs)
                
            except (AuthenticationError, RateLimitError):
                # Re-raise custom exceptions to be handled by error handlers
                raise
            except Exception as e:
                current_app.logger.error(f"Authentication middleware error: {str(e)}")
                raise AuthenticationError("Authentication failed")
        
        return decorated
    return decorator

def admin_required():
    """
    Decorator to require admin permissions
    """
    return jwt_required(permissions=['verified', 'admin'])

def verified_required():
    """
    Decorator to require verified email
    """
    return jwt_required(permissions=['verified'])

def optional_auth():
    """
    Decorator for optional authentication
    """
    return jwt_required(optional=True)

def rate_limited(max_requests=100, window_minutes=15):
    """
    Decorator for rate limiting without authentication requirement
    
    Args:
        max_requests (int): Maximum requests allowed
        window_minutes (int): Time window in minutes
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            client_ip = auth_middleware.get_client_ip(request)
            
            if auth_middleware.is_rate_limited(
                f"ip:{client_ip}", 
                max_requests, 
                window_minutes
            ):
                raise RateLimitError(
                    f"Rate limit exceeded. Maximum {max_requests} requests per {window_minutes} minutes."
                )
            
            return f(*args, **kwargs)
        return decorated
    return decorator

def validate_json(required_fields=None, optional_fields=None):
    """
    Decorator to validate JSON request data
    
    Args:
        required_fields (list): List of required field names
        optional_fields (dict): Dict of optional fields with default values
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not request.is_json:
                return jsonify({
                    'success': False,
                    'error': 'Content-Type must be application/json'
                }), 400
            
            data = request.get_json()
            if not data:
                return jsonify({
                    'success': False,
                    'error': 'Request body must contain valid JSON'
                }), 400
            
            # Check required fields
            if required_fields:
                missing_fields = []
                for field in required_fields:
                    value = data.get(field)
                    if value is None or (isinstance(value, str) and not value.strip()):
                        missing_fields.append(field)
                
                if missing_fields:
                    return jsonify({
                        'success': False,
                        'error': f'Missing required fields: {", ".join(missing_fields)}'
                    }), 400
            
            # Add optional fields with defaults
            if optional_fields:
                for field, default_value in optional_fields.items():
                    if field not in data:
                        data[field] = default_value
            
            # Add validated data to kwargs
            return f(data, *args, **kwargs)
        return decorated
    return decorator

# Helper function to get current user
def get_current_user():
    """Get current authenticated user from Flask's g object"""
    return getattr(g, 'current_user', None)

# Request context helpers
def require_ownership(model_class, id_field='id', user_field='user_id'):
    """
    Decorator to ensure user owns the resource they're trying to access
    
    Args:
        model_class: SQLAlchemy model class
        id_field: Field name for the resource ID in request
        user_field: Field name for user ID in the model
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            current_user = get_current_user()
            if not current_user:
                raise AuthenticationError("Authentication required")
            
            # Get resource ID from kwargs or request
            resource_id = kwargs.get(id_field) or request.view_args.get(id_field)
            if not resource_id:
                return jsonify({
                    'success': False,
                    'error': f'Missing {id_field} parameter'
                }), 400
            
            # Find the resource
            resource = model_class.query.get(resource_id)
            if not resource:
                return jsonify({
                    'success': False,
                    'error': 'Resource not found'
                }), 404
            
            # Check ownership
            if getattr(resource, user_field) != current_user.id:
                raise AuthenticationError("Access denied - you don't own this resource", 403)
            
            # Add resource to kwargs
            kwargs['resource'] = resource
            return f(*args, **kwargs)
        return decorated
    return decorator