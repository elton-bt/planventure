#!/usr/bin/env python3
"""
Database migration script for PlanVenture API
Updates database schema to match current models
"""
import os
import sqlite3
from datetime import datetime, timezone
from app import create_app
from database import db
from models.user import User
from models.viagem import Viagem

def get_db_path():
    """Get database file path"""
    app = create_app()
    db_url = app.config['SQLALCHEMY_DATABASE_URI']
    if db_url.startswith('sqlite:///'):
        return db_url.replace('sqlite:///', '')
    return 'planventure.db'

def check_column_exists(cursor, table_name, column_name):
    """Check if a column exists in a table"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [column[1] for column in cursor.fetchall()]
    return column_name in columns

def migrate_database():
    """Migrate database schema"""
    app = create_app()
    db_path = get_db_path()
    
    print(f"🔄 Starting database migration...")
    print(f"📁 Database path: {db_path}")
    
    # Connect directly to SQLite
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check what tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [table[0] for table in cursor.fetchall()]
        print(f"📊 Found tables: {tables}")
        
        # Migrate users table
        if 'users' in tables:
            print("🔄 Migrating users table...")
            
            # Check and add missing columns
            missing_columns = []
            
            # Email verification fields
            if not check_column_exists(cursor, 'users', 'email_verification_token'):
                missing_columns.append("ADD COLUMN email_verification_token VARCHAR(255)")
            
            if not check_column_exists(cursor, 'users', 'email_verification_sent_at'):
                missing_columns.append("ADD COLUMN email_verification_sent_at DATETIME")
            
            # Password reset fields
            if not check_column_exists(cursor, 'users', 'password_reset_token'):
                missing_columns.append("ADD COLUMN password_reset_token VARCHAR(255)")
            
            if not check_column_exists(cursor, 'users', 'password_reset_sent_at'):
                missing_columns.append("ADD COLUMN password_reset_sent_at DATETIME")
            
            # Security fields
            if not check_column_exists(cursor, 'users', 'failed_login_attempts'):
                missing_columns.append("ADD COLUMN failed_login_attempts INTEGER DEFAULT 0")
            
            if not check_column_exists(cursor, 'users', 'account_locked_until'):
                missing_columns.append("ADD COLUMN account_locked_until DATETIME")
            
            if not check_column_exists(cursor, 'users', 'last_login_at'):
                missing_columns.append("ADD COLUMN last_login_at DATETIME")
            
            if not check_column_exists(cursor, 'users', 'last_login_ip'):
                missing_columns.append("ADD COLUMN last_login_ip VARCHAR(45)")
            
            # Refresh tokens
            if not check_column_exists(cursor, 'users', 'refresh_tokens'):
                missing_columns.append("ADD COLUMN refresh_tokens TEXT")
            
            # Password salt
            if not check_column_exists(cursor, 'users', 'password_salt'):
                missing_columns.append("ADD COLUMN password_salt VARCHAR(64)")
            
            # Username
            if not check_column_exists(cursor, 'users', 'username'):
                missing_columns.append("ADD COLUMN username VARCHAR(80)")
            
            # Account status
            if not check_column_exists(cursor, 'users', 'is_active'):
                missing_columns.append("ADD COLUMN is_active BOOLEAN DEFAULT 1")
            
            if not check_column_exists(cursor, 'users', 'is_verified'):
                missing_columns.append("ADD COLUMN is_verified BOOLEAN DEFAULT 0")
            
            # Add missing columns
            for column_def in missing_columns:
                try:
                    cursor.execute(f"ALTER TABLE users {column_def}")
                    print(f"  ✅ Added: {column_def}")
                except sqlite3.Error as e:
                    print(f"  ⚠️  Warning: {column_def} - {e}")
            
            # Update existing users to have salt (for users created without salt)
            cursor.execute("SELECT id, password_hash, password_salt FROM users WHERE password_salt IS NULL")
            users_without_salt = cursor.fetchall()
            
            for user_id, password_hash, password_salt in users_without_salt:
                if password_salt is None:
                    # Generate a default salt for existing users
                    import secrets
                    new_salt = secrets.token_hex(32)
                    cursor.execute(
                        "UPDATE users SET password_salt = ?, failed_login_attempts = 0 WHERE id = ?",
                        (new_salt, user_id)
                    )
                    print(f"  🔐 Added salt for user ID {user_id}")
        
        # Migrate viagens table
        if 'viagens' in tables:
            print("🔄 Migrating viagens table...")
            
            viagem_missing_columns = []
            
            # Check for missing columns in viagens
            if not check_column_exists(cursor, 'viagens', 'latitude'):
                viagem_missing_columns.append("ADD COLUMN latitude FLOAT")
            
            if not check_column_exists(cursor, 'viagens', 'longitude'):
                viagem_missing_columns.append("ADD COLUMN longitude FLOAT")
            
            if not check_column_exists(cursor, 'viagens', 'itinerario'):
                viagem_missing_columns.append("ADD COLUMN itinerario TEXT")
            
            if not check_column_exists(cursor, 'viagens', 'titulo'):
                viagem_missing_columns.append("ADD COLUMN titulo VARCHAR(150)")
            
            if not check_column_exists(cursor, 'viagens', 'descricao'):
                viagem_missing_columns.append("ADD COLUMN descricao TEXT")
            
            if not check_column_exists(cursor, 'viagens', 'budget'):
                viagem_missing_columns.append("ADD COLUMN budget FLOAT")
            
            if not check_column_exists(cursor, 'viagens', 'status'):
                viagem_missing_columns.append("ADD COLUMN status VARCHAR(20) DEFAULT 'planejando'")
            
            if not check_column_exists(cursor, 'viagens', 'is_public'):
                viagem_missing_columns.append("ADD COLUMN is_public BOOLEAN DEFAULT 0")
            
            if not check_column_exists(cursor, 'viagens', 'created_at'):
                viagem_missing_columns.append("ADD COLUMN created_at DATETIME")
            
            if not check_column_exists(cursor, 'viagens', 'updated_at'):
                viagem_missing_columns.append("ADD COLUMN updated_at DATETIME")
            
            # Add missing columns to viagens
            for column_def in viagem_missing_columns:
                try:
                    cursor.execute(f"ALTER TABLE viagens {column_def}")
                    print(f"  ✅ Added: {column_def}")
                except sqlite3.Error as e:
                    print(f"  ⚠️  Warning: {column_def} - {e}")
            
            # Update viagens without timestamps
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute("UPDATE viagens SET created_at = ?, updated_at = ? WHERE created_at IS NULL", (now, now))
            cursor.execute("UPDATE viagens SET status = 'planejando' WHERE status IS NULL")
        
        # Create indexes for better performance
        print("🔄 Creating indexes...")
        
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users(email_verification_token)",
            "CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users(password_reset_token)",
            "CREATE INDEX IF NOT EXISTS idx_viagens_user_id ON viagens(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_viagens_status ON viagens(status)",
            "CREATE INDEX IF NOT EXISTS idx_viagens_public ON viagens(is_public)",
            "CREATE INDEX IF NOT EXISTS idx_viagens_dates ON viagens(data_inicio, data_fim)"
        ]
        
        for index_sql in indexes:
            try:
                cursor.execute(index_sql)
                print(f"  ✅ Created index")
            except sqlite3.Error as e:
                print(f"  ⚠️  Index warning: {e}")
        
        # Commit changes
        conn.commit()
        print("✅ Database migration completed successfully!")
        
        # Show final table structure
        print("\n📊 Final table structures:")
        for table in ['users', 'viagens']:
            if table in tables:
                cursor.execute(f"PRAGMA table_info({table})")
                columns = cursor.fetchall()
                print(f"\n{table.upper()}:")
                for col in columns:
                    print(f"  {col[1]} ({col[2]})")
    
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        conn.rollback()
        raise
    
    finally:
        conn.close()

def verify_migration():
    """Verify migration was successful"""
    print("\n🔍 Verifying migration...")
    
    app = create_app()
    with app.app_context():
        try:
            # Test user operations
            user_count = User.query.count()
            print(f"  ✅ Users table: {user_count} records")
            
            # Test viagem operations
            viagem_count = Viagem.query.count()
            print(f"  ✅ Viagens table: {viagem_count} records")
            
            # Test creating a test user
            test_email = "migration_test@example.com"
            existing_user = User.find_by_email(test_email)
            if existing_user:
                db.session.delete(existing_user)
                db.session.commit()
            
            test_user = User.create_user(
                email=test_email,
                password="TestPassword123!",
                first_name="Migration",
                last_name="Test"
            )
            
            # Test token generation
            tokens = test_user.generate_tokens()
            print(f"  ✅ Token generation: Working")
            
            # Clean up test user
            db.session.delete(test_user)
            db.session.commit()
            
            print("  ✅ Migration verification completed successfully!")
            
        except Exception as e:
            print(f"  ❌ Verification failed: {e}")
            raise

if __name__ == '__main__':
    migrate_database()
    verify_migration()