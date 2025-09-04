from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
import re

# Import db from database module instead of creating a new instance
from database import db

class User(db.Model):
    __tablename__ = 'users'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # User credentials
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # User profile
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=True, index=True)
    
    # Status fields
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    
    def __init__(self, email, password, first_name=None, last_name=None, username=None):
        self.email = email.lower().strip()
        self.set_password(password)
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    def set_password(self, password):
        """Hash and set password"""
        if not password or len(password) < 6:
            raise ValueError("Password must be at least 6 characters long")
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)
    
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
    
    def to_dict(self, include_timestamps=True):
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
        
        # Create user
        user = cls(email=email, password=password, **kwargs)
        db.session.add(user)
        db.session.commit()
        
        return user