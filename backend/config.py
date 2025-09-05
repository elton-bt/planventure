import os
from datetime import timedelta
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_cors import CORS

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///planventure-dev.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_ALGORITHM = 'HS256'
    
    CORS_ORIGINS = '*'
    # Novas chaves CORS
    CORS_RESOURCES = {r"/api/*": {"origins": "*"}}
    CORS_SUPPORTS_CREDENTIALS = False  # Se precisar cookies, mudar para True e restringir origens
    CORS_ALLOW_HEADERS = ["Content-Type", "Authorization"]
    CORS_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

class DevelopmentConfig(Config):
    DEBUG = True
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DB_PATH = os.path.join(BASE_DIR, "planventure-dev.db")
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_PATH}"

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///planventure.db')

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/planventure.log', maxBytes=10*1024*1024, backupCount=10)

def create_app(config_name=None):
    """Application factory"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    
    # Initialize CORS (permitir qualquer origem para frontend React)
    CORS(
        app,
        resources=app.config.get('CORS_RESOURCES', {r"/api/*": {"origins": "*"}}),
        origins=app.config.get('CORS_ORIGINS', '*'),
        supports_credentials=app.config.get('CORS_SUPPORTS_CREDENTIALS', False),
        allow_headers=app.config.get('CORS_ALLOW_HEADERS', ["Content-Type", "Authorization"]),
        methods=app.config.get('CORS_METHODS', ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    )
    
    # Initialize database
    db = init_db(app)

    return app
