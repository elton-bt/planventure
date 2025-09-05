from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()

def init_db(app):
    """Initialize database with Flask app"""
    db.init_app(app)
    migrate.init_app(app, db)
    
    # Import all models to register them with SQLAlchemy
    from models.user import User
    from models.viagem import Viagem
    
    return db

def create_tables(app):
    """Create all tables (only if they don't exist)"""
    with app.app_context():
        db.create_all()

def drop_tables(app):
    """Drop all tables"""
    with app.app_context():
        db.drop_all()

def reset_database(app):
    """Reset database (drop and recreate all tables)"""
    with app.app_context():
        db.drop_all()
        db.create_all()