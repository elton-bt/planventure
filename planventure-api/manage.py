#!/usr/bin/env python3
"""
Database management script for PlanVenture API
"""
import sys
import os
from flask.cli import with_appcontext
import click
from datetime import datetime, date

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from database import db
from models.user import User
from models.viagem import Viagem

def get_app():
    """Get Flask app instance"""
    config_name = os.environ.get('FLASK_ENV', 'development')
    return create_app(config_name)

@click.group()
def cli():
    """Database management commands"""
    pass

# Database commands
@cli.command()
@click.option('--drop', is_flag=True, help='Drop all tables before creating')
def init_db(drop):
    """Initialize database tables"""
    app = get_app()
    
    with app.app_context():
        if drop:
            click.echo('Dropping all tables...')
            db.drop_all()
            click.echo('✓ Tables dropped')
        
        click.echo('Creating database tables...')
        db.create_all()
        click.echo('✓ Database tables created successfully')

@cli.command()
def drop_db():
    """Drop all database tables"""
    app = get_app()
    
    if click.confirm('Are you sure you want to drop all tables? This will delete all data.'):
        with app.app_context():
            click.echo('Dropping all tables...')
            db.drop_all()
            click.echo('✓ All tables dropped')
    else:
        click.echo('Operation cancelled')

@cli.command()
def reset_db():
    """Reset database (drop and recreate all tables)"""
    app = get_app()
    
    if click.confirm('Are you sure you want to reset the database? This will delete all data.'):
        with app.app_context():
            click.echo('Resetting database...')
            db.drop_all()
            db.create_all()
            click.echo('✓ Database reset completed')
    else:
        click.echo('Operation cancelled')

# User commands
@cli.command()
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
                # You can add admin role logic here if needed
                click.echo(f'✓ Admin user created: {user.email}')
            else:
                click.echo(f'✓ User created: {user.email}')
                
        except ValueError as e:
            click.echo(f'✗ Error: {str(e)}', err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f'✗ Unexpected error: {str(e)}', err=True)
            sys.exit(1)

@cli.command()
def list_users():
    """List all users"""
    app = get_app()
    
    with app.app_context():
        users = User.query.all()
        if users:
            click.echo(f"Found {len(users)} users:")
            for user in users:
                click.echo(f"  ID: {user.id}, Email: {user.email}, Name: {user.full_name}, Active: {user.is_active}")
        else:
            click.echo("No users found")

@cli.command()
@click.argument('user_id', type=int)
def delete_user(user_id):
    """Delete a user by ID"""
    app = get_app()
    
    with app.app_context():
        user = User.query.get(user_id)
        if user:
            if click.confirm(f'Are you sure you want to delete user {user.email}?'):
                # This will also delete all associated trips due to cascade
                db.session.delete(user)
                db.session.commit()
                click.echo(f'✓ User {user.email} deleted')
            else:
                click.echo('Operation cancelled')
        else:
            click.echo(f'✗ User with ID {user_id} not found')

# Trip commands
@cli.command()
@click.option('--user-email', prompt='User email', help='User email')
@click.option('--destino', prompt='Destination', help='Trip destination')
@click.option('--data-inicio', prompt='Start date (YYYY-MM-DD)', help='Trip start date')
@click.option('--data-fim', prompt='End date (YYYY-MM-DD)', help='Trip end date')
@click.option('--titulo', help='Trip title')
@click.option('--descricao', help='Trip description')
@click.option('--latitude', type=float, help='Latitude')
@click.option('--longitude', type=float, help='Longitude')
@click.option('--budget', type=float, help='Trip budget')
@click.option('--public', is_flag=True, help='Make trip public')
def create_viagem(user_email, destino, data_inicio, data_fim, titulo, descricao, latitude, longitude, budget, public):
    """Create a new trip"""
    app = get_app()
    
    with app.app_context():
        try:
            # Find user
            user = User.find_by_email(user_email)
            if not user:
                click.echo(f'✗ User with email {user_email} not found')
                sys.exit(1)
            
            # Parse dates
            try:
                data_inicio = datetime.strptime(data_inicio, '%Y-%m-%d').date()
                data_fim = datetime.strptime(data_fim, '%Y-%m-%d').date()
            except ValueError:
                click.echo('✗ Invalid date format. Use YYYY-MM-DD')
                sys.exit(1)
            
            # Create trip
            kwargs = {}
            if titulo:
                kwargs['titulo'] = titulo
            if descricao:
                kwargs['descricao'] = descricao
            if latitude is not None and longitude is not None:
                kwargs['latitude'] = latitude
                kwargs['longitude'] = longitude
            if budget is not None:
                kwargs['budget'] = budget
            if public:
                kwargs['is_public'] = True
            
            viagem = Viagem.create_viagem(
                user_id=user.id,
                destino=destino,
                data_inicio=data_inicio,
                data_fim=data_fim,
                **kwargs
            )
            
            click.echo(f'✓ Trip created: {viagem.titulo or viagem.destino} for {user.email}')
            click.echo(f'  Duration: {viagem.duracao_dias} days')
            if viagem.coordenadas:
                click.echo(f'  Coordinates: {viagem.coordenadas}')
                
        except ValueError as e:
            click.echo(f'✗ Error: {str(e)}', err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f'✗ Unexpected error: {str(e)}', err=True)
            sys.exit(1)

@cli.command()
@click.option('--user-email', help='Filter by user email')
@click.option('--status', help='Filter by status')
@click.option('--public-only', is_flag=True, help='Show only public trips')
def list_viagens(user_email, status, public_only):
    """List trips"""
    app = get_app()
    
    with app.app_context():
        query = Viagem.query
        
        if user_email:
            user = User.find_by_email(user_email)
            if user:
                query = query.filter_by(user_id=user.id)
            else:
                click.echo(f'✗ User with email {user_email} not found')
                return
        
        if status:
            query = query.filter_by(status=status)
        
        if public_only:
            query = query.filter_by(is_public=True)
        
        viagens = query.all()
        
        if viagens:
            click.echo(f"Found {len(viagens)} trips:")
            for viagem in viagens:
                user_info = f"{viagem.user.email}" if viagem.user else "Unknown"
                click.echo(f"  ID: {viagem.id}")
                click.echo(f"  User: {user_info}")
                click.echo(f"  Destination: {viagem.destino}")
                click.echo(f"  Title: {viagem.titulo or 'N/A'}")
                click.echo(f"  Dates: {viagem.data_inicio} to {viagem.data_fim} ({viagem.duracao_dias} days)")
                click.echo(f"  Status: {viagem.status}")
                click.echo(f"  Public: {viagem.is_public}")
                if viagem.coordenadas:
                    click.echo(f"  Coordinates: {viagem.coordenadas}")
                if viagem.budget:
                    click.echo(f"  Budget: ${viagem.budget}")
                click.echo("  ---")
        else:
            click.echo("No trips found")

@cli.command()
@click.argument('viagem_id', type=int)
def delete_viagem(viagem_id):
    """Delete a trip by ID"""
    app = get_app()
    
    with app.app_context():
        viagem = Viagem.query.get(viagem_id)
        if viagem:
            if click.confirm(f'Are you sure you want to delete trip "{viagem.titulo or viagem.destino}"?'):
                viagem.delete_viagem()
                click.echo(f'✓ Trip deleted')
            else:
                click.echo('Operation cancelled')
        else:
            click.echo(f'✗ Trip with ID {viagem_id} not found')

# Utility commands
@cli.command()
def show_config():
    """Show current configuration"""
    app = get_app()
    click.echo(f"Environment: {app.config.get('ENV', 'unknown')}")
    click.echo(f"Debug: {app.config.get('DEBUG', False)}")
    click.echo(f"Database URI: {app.config.get('SQLALCHEMY_DATABASE_URI', 'Not set')}")
    click.echo(f"Secret Key: {'Set' if app.config.get('SECRET_KEY') else 'Not set'}")

@cli.command()
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

if __name__ == '__main__':
    cli()