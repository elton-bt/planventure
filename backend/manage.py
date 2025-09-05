#!/usr/bin/env python3
"""
Database management script for PlanVenture API
"""
import sys
import os
import click
from datetime import datetime, date

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from database import db, reset_database, create_tables, drop_tables
from models.user import User
from models.viagem import Viagem

def get_app():
    """Get Flask app instance"""
    return create_app()

@click.group()
def cli():
    """PlanVenture API Management Commands"""
    pass

# Database commands
@cli.command('init_db')  # Usar underscore em vez de hífen
def init_db():
    """Initialize database tables"""
    app = get_app()
    
    with app.app_context():
        try:
            create_tables(app)
            click.echo('✓ Database initialized successfully')
        except Exception as e:
            click.echo(f'✗ Database initialization failed: {str(e)}')
            sys.exit(1)

@cli.command('check_db')  # Usar underscore em vez de hífen
def check_db():
    """Check database connection and table status"""
    app = get_app()
    
    with app.app_context():
        try:
            # Test connection with proper text() wrapper
            from sqlalchemy import text
            db.session.execute(text('SELECT 1'))
            click.echo('✓ Database connection: OK')
            
            # Check tables
            users_count = User.query.count()
            viagens_count = Viagem.query.count()
            
            click.echo(f'✓ Users table: {users_count} records')
            click.echo(f'✓ Viagens table: {viagens_count} records')
            
        except Exception as e:
            click.echo(f'✗ Database error: {str(e)}')

@cli.command('list_users')  # Usar underscore em vez de hífen
def list_users():
    """List all users"""
    app = get_app()
    
    with app.app_context():
        try:
            users = User.query.all()
            if users:
                click.echo(f"Found {len(users)} users:")
                for user in users:
                    click.echo(f"  ID: {user.id}")
                    click.echo(f"  Email: {user.email}")
                    click.echo(f"  Name: {user.full_name}")
                    click.echo(f"  Active: {user.is_active}")
                    click.echo(f"  Verified: {user.is_verified}")
                    click.echo(f"  Created: {user.created_at}")
                    click.echo("  ---")
            else:
                click.echo("No users found")
        except Exception as e:
            click.echo(f'✗ Error listing users: {str(e)}')

@cli.command('create_user')  # Usar underscore em vez de hífen
@click.option('--email', prompt='Email', help='User email')
@click.option('--password', prompt='Password', hide_input=True, help='User password')
@click.option('--first-name', help='First name')
@click.option('--last-name', help='Last name')
@click.option('--username', help='Username')
@click.option('--admin', is_flag=True, help='Create as admin user')
def create_user(email, password, first_name, last_name, username, admin):
    """Create a new user"""
    app = get_app()
    
    with app.app_context():
        try:
            user = User.create_user(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                username=username
            )
            
            if admin:
                click.echo(f'✓ Admin user created: {user.email}')
            else:
                click.echo(f'✓ User created: {user.email}')
                
        except ValueError as e:
            click.echo(f'✗ Error: {str(e)}', err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f'✗ Unexpected error: {str(e)}', err=True)
            sys.exit(1)

@cli.command('reset_db')  # Usar underscore em vez de hífen
def reset_db():
    """Reset database (drop and recreate all tables)"""
    app = get_app()
    
    if click.confirm('This will delete all data. Are you sure?'):
        with app.app_context():
            try:
                reset_database(app)
                click.echo('✓ Database reset successfully')
            except Exception as e:
                click.echo(f'✗ Database reset failed: {str(e)}')
                sys.exit(1)
    else:
        click.echo('Operation cancelled')

if __name__ == '__main__':
    cli()