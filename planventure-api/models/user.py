from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import re
import secrets
import hashlib
import hmac
import base64
import jwt
import os

# Import db from database module instead of creating a new instance
from database import db

class JWTUtils:
    """Utility class for JWT token generation and validation"""
    
    @staticmethod
    def get_jwt_secret():
        """Get JWT secret key from environment or config"""
        return os.environ.get('JWT_SECRET_KEY', os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production'))
    
    @staticmethod
    def get_jwt_algorithm():
        """Get JWT algorithm from environment or default"""
        return os.environ.get('JWT_ALGORITHM', 'HS256')
    
    @staticmethod
    def get_access_token_expiry():
        """Get access token expiry time in hours"""
        return int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES_HOURS', 1))
    
    @staticmethod
    def get_refresh_token_expiry():
        """Get refresh token expiry time in days"""
        return int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES_DAYS', 30))
    
    @staticmethod
    def generate_access_token(user_id, email, additional_claims=None):
        """
        Generate JWT access token
        
        Args:
            user_id (int): User ID
            email (str): User email
            additional_claims (dict, optional): Additional claims to include
            
        Returns:
            str: JWT access token
        """
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(hours=JWTUtils.get_access_token_expiry())
        
        payload = {
            'user_id': user_id,
            'email': email,
            'iat': now,
            'exp': expiry,
            'type': 'access',
            'jti': secrets.token_hex(16)  # JWT ID for token revocation
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        return jwt.encode(
            payload,
            JWTUtils.get_jwt_secret(),
            algorithm=JWTUtils.get_jwt_algorithm()
        )
    
    @staticmethod
    def generate_refresh_token(user_id, email):
        """
        Generate JWT refresh token
        
        Args:
            user_id (int): User ID
            email (str): User email
            
        Returns:
            str: JWT refresh token
        """
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(days=JWTUtils.get_refresh_token_expiry())
        
        payload = {
            'user_id': user_id,
            'email': email,
            'iat': now,
            'exp': expiry,
            'type': 'refresh',
            'jti': secrets.token_hex(16)
        }
        
        return jwt.encode(
            payload,
            JWTUtils.get_jwt_secret(),
            algorithm=JWTUtils.get_jwt_algorithm()
        )
    
    @staticmethod
    def verify_token(token, expected_type='access'):
        """
        Verify and decode JWT token
        
        Args:
            token (str): JWT token to verify
            expected_type (str): Expected token type ('access' or 'refresh')
            
        Returns:
            dict: Decoded payload if valid, None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                JWTUtils.get_jwt_secret(),
                algorithms=[JWTUtils.get_jwt_algorithm()]
            )
            
            # Check token type
            if payload.get('type') != expected_type:
                return None
            
            # Check if token is expired (JWT library handles this, but double check)
            if datetime.fromtimestamp(payload['exp'], tz=timezone.utc) < datetime.now(timezone.utc):
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception:
            return None
    
    @staticmethod
    def decode_token_without_verification(token):
        """
        Decode token without verification (for debugging)
        
        Args:
            token (str): JWT token
            
        Returns:
            dict: Decoded payload or None
        """
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception:
            return None
    
    @staticmethod
    def is_token_expired(token):
        """
        Check if token is expired without full verification
        
        Args:
            token (str): JWT token
            
        Returns:
            bool: True if expired, False if valid, None if invalid
        """
        payload = JWTUtils.decode_token_without_verification(token)
        if not payload:
            return None
        
        try:
            exp_timestamp = payload.get('exp')
            if not exp_timestamp:
                return None
            
            exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
            return exp_datetime < datetime.now(timezone.utc)
        except Exception:
            return None

class PasswordUtils:
    """Utility class for password hashing and salt generation"""
    
    @staticmethod
    def generate_salt(length=32):
        """Generate a cryptographically secure random salt"""
        return secrets.token_hex(length)
    
    @staticmethod
    def generate_pepper():
        """Generate a pepper (application-wide secret)"""
        import os
        return os.environ.get('PASSWORD_PEPPER', 'default-pepper-change-in-production')
    
    @staticmethod
    def hash_password_with_salt(password, salt=None, pepper=None):
        """
        Hash password with salt and pepper using PBKDF2
        
        Args:
            password (str): Plain text password
            salt (str, optional): Salt for hashing. If None, generates new salt
            pepper (str, optional): Application-wide pepper. If None, uses default
        
        Returns:
            dict: Contains 'hash', 'salt', and 'algorithm' information
        """
        if salt is None:
            salt = PasswordUtils.generate_salt()
        
        if pepper is None:
            pepper = PasswordUtils.generate_pepper()
        
        # Combine password with pepper
        password_with_pepper = password + pepper
        
        # Use PBKDF2 with SHA256
        hash_value = hashlib.pbkdf2_hmac(
            'sha256',
            password_with_pepper.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # 100,000 iterations
        )
        
        # Encode to base64 for storage
        hash_b64 = base64.b64encode(hash_value).decode('utf-8')
        
        return {
            'hash': hash_b64,
            'salt': salt,
            'algorithm': 'pbkdf2_sha256',
            'iterations': 100000
        }
    
    @staticmethod
    def verify_password_with_salt(password, stored_hash, salt, pepper=None):
        """
        Verify password against stored hash with salt and pepper
        
        Args:
            password (str): Plain text password to verify
            stored_hash (str): Base64 encoded stored hash
            salt (str): Salt used in original hash
            pepper (str, optional): Application-wide pepper
        
        Returns:
            bool: True if password matches, False otherwise
        """
        if pepper is None:
            pepper = PasswordUtils.generate_pepper()
        
        # Hash the provided password with the same salt
        password_with_pepper = password + pepper
        hash_value = hashlib.pbkdf2_hmac(
            'sha256',
            password_with_pepper.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        
        # Encode to base64 for comparison
        hash_b64 = base64.b64encode(hash_value).decode('utf-8')
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored_hash, hash_b64)
    
    @staticmethod
    def generate_secure_token(length=32):
        """Generate a cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def validate_password_strength(password):
        """
        Validate password strength
        
        Returns:
            dict: Contains 'valid' boolean and 'errors' list
        """
        errors = []
        
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        
        if len(password) > 128:
            errors.append("Password must be less than 128 characters")
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # Check for common patterns
        if password.lower() in ['password', '12345678', 'qwerty', 'abc123']:
            errors.append("Password is too common")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'strength': PasswordUtils._calculate_password_strength(password)
        }
    
    @staticmethod
    def _calculate_password_strength(password):
        """Calculate password strength score (0-100)"""
        score = 0
        
        # Length bonus
        score += min(password and len(password) * 2, 20)
        
        # Character variety
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 20
        
        # Bonus for mix of character types
        char_types = sum([
            bool(re.search(r'[a-z]', password)),
            bool(re.search(r'[A-Z]', password)),
            bool(re.search(r'\d', password)),
            bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        ])
        
        if char_types >= 3:
            score += 10
        if char_types == 4:
            score += 10
        
        # Penalty for repetitive patterns
        if re.search(r'(.)\1{2,}', password):  # Same character repeated 3+ times
            score -= 10
        
        return min(100, max(0, score))

class User(db.Model):
    __tablename__ = 'users'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # User credentials
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    password_salt = db.Column(db.String(64), nullable=False)  # Store salt separately
    
    # User profile
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=True, index=True)
    
    # Security fields
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    password_reset_token = db.Column(db.String(255), nullable=True)
    password_reset_expires = db.Column(db.DateTime, nullable=True)
    
    # JWT token management
    refresh_token_jti = db.Column(db.String(255), nullable=True)  # Store current refresh token JTI
    refresh_token_expires = db.Column(db.DateTime, nullable=True)
    
    # Email verification
    email_verification_token = db.Column(db.String(255), nullable=True)
    email_verification_expires = db.Column(db.DateTime, nullable=True)
    
    # Status fields
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationship with Viagem
    viagens = db.relationship('Viagem', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __init__(self, email, password, first_name=None, last_name=None, username=None):
        self.email = email.lower().strip()
        self.set_password(password)
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.failed_login_attempts = 0
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    def set_password(self, password, validate_strength=True):
        """
        Hash and set password with salt
        
        Args:
            password (str): Plain text password
            validate_strength (bool): Whether to validate password strength
        """
        if validate_strength:
            validation = PasswordUtils.validate_password_strength(password)
            if not validation['valid']:
                raise ValueError(f"Password validation failed: {'; '.join(validation['errors'])}")
        
        if not password or len(password) < 6:
            raise ValueError("Password must be at least 6 characters long")
        
        # Generate new salt and hash
        hash_data = PasswordUtils.hash_password_with_salt(password)
        self.password_hash = hash_data['hash']
        self.password_salt = hash_data['salt']
        self.password_changed_at = datetime.now(timezone.utc)
        
        # Reset failed login attempts when password is changed
        self.failed_login_attempts = 0
        self.account_locked_until = None
        
        # Invalidate existing refresh tokens when password changes
        self.invalidate_refresh_tokens()
    
    def check_password(self, password):
        """
        Check if provided password matches hash
        
        Args:
            password (str): Plain text password to verify
            
        Returns:
            bool: True if password matches, False otherwise
        """
        if self.is_account_locked():
            return False
        
        is_valid = PasswordUtils.verify_password_with_salt(
            password, 
            self.password_hash, 
            self.password_salt
        )
        
        if is_valid:
            # Reset failed attempts on successful login
            self.failed_login_attempts = 0
            self.account_locked_until = None
            self.update_last_login()
        else:
            # Increment failed attempts
            self.increment_failed_login_attempts()
        
        return is_valid
    
    # JWT Token Methods
    def generate_tokens(self, additional_claims=None):
        """
        Generate both access and refresh tokens
        
        Args:
            additional_claims (dict, optional): Additional claims for access token
            
        Returns:
            dict: Contains 'access_token' and 'refresh_token'
        """
        access_token = JWTUtils.generate_access_token(
            self.id, 
            self.email, 
            additional_claims
        )
        refresh_token = JWTUtils.generate_refresh_token(self.id, self.email)
        
        # Store refresh token JTI and expiry
        refresh_payload = JWTUtils.decode_token_without_verification(refresh_token)
        if refresh_payload:
            self.refresh_token_jti = refresh_payload.get('jti')
            self.refresh_token_expires = datetime.fromtimestamp(
                refresh_payload['exp'], tz=timezone.utc
            )
            db.session.commit()
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': JWTUtils.get_access_token_expiry() * 3600,  # in seconds
            'user': self.to_dict(include_timestamps=False)
        }
    
    def verify_refresh_token(self, refresh_token):
        """
        Verify refresh token belongs to this user
        
        Args:
            refresh_token (str): Refresh token to verify
            
        Returns:
            bool: True if valid, False otherwise
        """
        payload = JWTUtils.verify_token(refresh_token, 'refresh')
        if not payload:
            return False
        
        # Check if token belongs to this user
        if payload.get('user_id') != self.id or payload.get('email') != self.email:
            return False
        
        # Check if this is the current refresh token
        if payload.get('jti') != self.refresh_token_jti:
            return False
        
        return True
    
    def refresh_access_token(self, refresh_token):
        """
        Generate new access token using refresh token
        
        Args:
            refresh_token (str): Valid refresh token
            
        Returns:
            dict: New access token data or None if invalid
        """
        if not self.verify_refresh_token(refresh_token):
            return None
        
        # Generate new access token
        access_token = JWTUtils.generate_access_token(self.id, self.email)
        
        return {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': JWTUtils.get_access_token_expiry() * 3600
        }
    
    def invalidate_refresh_tokens(self):
        """Invalidate all refresh tokens for this user"""
        self.refresh_token_jti = None
        self.refresh_token_expires = None
        db.session.commit()
    
    def is_refresh_token_expired(self):
        """Check if stored refresh token is expired"""
        if not self.refresh_token_expires:
            return True
        return datetime.now(timezone.utc) > self.refresh_token_expires
    
    @classmethod
    def get_user_from_token(cls, access_token):
        """
        Get user from access token
        
        Args:
            access_token (str): JWT access token
            
        Returns:
            User: User object if valid, None otherwise
        """
        payload = JWTUtils.verify_token(access_token, 'access')
        if not payload:
            return None
        
        user_id = payload.get('user_id')
        if not user_id:
            return None
        
        user = cls.query.get(user_id)
        if not user or not user.is_active:
            return None
        
        return user
    
    def logout(self):
        """Logout user by invalidating refresh tokens"""
        self.invalidate_refresh_tokens()
    
    # Existing methods remain the same...
    def increment_failed_login_attempts(self):
        """Increment failed login attempts and lock account if necessary"""
        self.failed_login_attempts += 1
        
        # Lock account after 5 failed attempts for 30 minutes
        if self.failed_login_attempts >= 5:
            self.account_locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
        
        db.session.commit()
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.account_locked_until is None:
            return False
        
        if datetime.now(timezone.utc) > self.account_locked_until:
            # Lock period has expired, reset
            self.account_locked_until = None
            self.failed_login_attempts = 0
            db.session.commit()
            return False
        
        return True
    
    def generate_password_reset_token(self):
        """Generate and store a password reset token"""
        self.password_reset_token = PasswordUtils.generate_secure_token(48)
        self.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)  # 1 hour expiry
        db.session.commit()
        
        return self.password_reset_token
    
    def verify_password_reset_token(self, token):
        """Verify password reset token"""
        if not self.password_reset_token or not self.password_reset_expires:
            return False
        
        if datetime.now(timezone.utc) > self.password_reset_expires:
            # Token expired
            self.password_reset_token = None
            self.password_reset_expires = None
            db.session.commit()
            return False
        
        return hmac.compare_digest(self.password_reset_token, token)
    
    def reset_password_with_token(self, token, new_password):
        """Reset password using reset token"""
        if not self.verify_password_reset_token(token):
            raise ValueError("Invalid or expired reset token")
        
        self.set_password(new_password)
        
        # Clear reset token
        self.password_reset_token = None
        self.password_reset_expires = None
        
        db.session.commit()
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.now(timezone.utc)
        db.session.commit()
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @property
    def full_name(self):
        """Get full name"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.first_name or self.last_name or self.username or self.email
    
    @property
    def password_age_days(self):
        """Get password age in days"""
        if self.password_changed_at:
            return (datetime.now(timezone.utc) - self.password_changed_at).days
        return 0
    
    @property
    def needs_password_change(self, max_age_days=90):
        """Check if password needs to be changed based on age"""
        return self.password_age_days > max_age_days
    
    def to_dict(self, include_timestamps=True, include_security=False):
        """Convert user to dictionary (excluding sensitive data)"""
        data = {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'username': self.username,
            'full_name': self.full_name,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
        }
        
        if include_timestamps:
            data.update({
                'created_at': self.created_at.isoformat() if self.created_at else None,
                'updated_at': self.updated_at.isoformat() if self.updated_at else None,
                'last_login': self.last_login.isoformat() if self.last_login else None,
                'password_changed_at': self.password_changed_at.isoformat() if self.password_changed_at else None,
            })
        
        if include_security:
            data.update({
                'failed_login_attempts': self.failed_login_attempts,
                'is_account_locked': self.is_account_locked(),
                'password_age_days': self.password_age_days,
                'needs_password_change': self.needs_password_change(),
                'is_refresh_token_expired': self.is_refresh_token_expired(),
            })
        
        return data
    
    def to_json(self):
        """Convert to JSON-serializable dict"""
        return self.to_dict()
    
    @classmethod
    def find_by_email(cls, email):
        """Find user by email"""
        return cls.query.filter_by(email=email.lower().strip()).first()
    
    @classmethod
    def find_by_username(cls, username):
        """Find user by username"""
        return cls.query.filter_by(username=username).first()
    
    @classmethod
    def find_by_reset_token(cls, token):
        """Find user by password reset token"""
        return cls.query.filter_by(password_reset_token=token).first()
    
    @classmethod
    def find_by_verification_token(cls, token):
        """Find user by email verification token"""
        return cls.query.filter_by(email_verification_token=token).first()
    
    @classmethod
    def authenticate(cls, email, password):
        """
        Authenticate user and return tokens
        
        Args:
            email (str): User email
            password (str): User password
            
        Returns:
            dict: Authentication result with tokens or error
        """
        user = cls.find_by_email(email)
        if not user:
            return {'success': False, 'error': 'Invalid credentials'}
        
        if not user.is_active:
            return {'success': False, 'error': 'Account is deactivated'}
        
        if user.is_account_locked():
            return {'success': False, 'error': 'Account is temporarily locked due to too many failed attempts'}
        
        if not user.check_password(password):
            return {'success': False, 'error': 'Invalid credentials'}
        
        # Generate tokens
        tokens = user.generate_tokens()
        
        return {
            'success': True,
            'user': user,
            'tokens': tokens
        }
    
    @classmethod
    def create_user(cls, email, password, **kwargs):
        """Create new user with validation"""
        # Validate email
        if not cls.validate_email(email):
            raise ValueError("Invalid email format")
        
        # Check if email already exists
        if cls.find_by_email(email):
            raise ValueError("Email already registered")
        
        # Check if username already exists (if provided)
        username = kwargs.get('username')
        if username and cls.find_by_username(username):
            raise ValueError("Username already taken")
        
        # Create user (password validation happens in set_password)
        user = cls(email=email, password=password, **kwargs)
        db.session.add(user)
        db.session.commit()
        
        return user
    
    def generate_email_verification_token(self):
        """Generate and store an email verification token"""
        self.email_verification_token = PasswordUtils.generate_secure_token(48)
        self.email_verification_expires = datetime.now(timezone.utc) + timedelta(hours=24)  # 24 hour expiry
        db.session.commit()
        
        return self.email_verification_token
    
    def verify_email_verification_token(self, token):
        """Verify email verification token"""
        if not self.email_verification_token or not self.email_verification_expires:
            return False
        
        if datetime.now(timezone.utc) > self.email_verification_expires:
            # Token expired
            self.email_verification_token = None
            self.email_verification_expires = None
            db.session.commit()
            return False
        
        return hmac.compare_digest(self.email_verification_token, token)
    
    def verify_email_with_token(self, token):
        """Verify email using verification token"""
        if not self.verify_email_verification_token(token):
            raise ValueError("Invalid or expired verification token")
        
        self.is_verified = True
        
        # Clear verification token
        self.email_verification_token = None
        self.email_verification_expires = None
        
        db.session.commit()
        return True