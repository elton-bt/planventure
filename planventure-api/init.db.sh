#!/bin/bash

# Enhanced setup script for PlanVenture API

set -e

echo "🚀 PlanVenture API Setup"
echo "========================"

# Check operating system
OS=$(uname -s)
echo "🔍 Detected OS: $OS"

# Install system dependencies based on OS
install_system_deps() {
    case $OS in
        "Linux")
            if command -v apt-get &> /dev/null; then
                echo "📦 Installing system dependencies (Ubuntu/Debian)..."
                sudo apt-get update
                sudo apt-get install -y \
                    python3-dev \
                    python3-pip \
                    python3-venv \
                    build-essential \
                    libffi-dev \
                    libssl-dev \
                    pkg-config
            elif command -v yum &> /dev/null; then
                echo "📦 Installing system dependencies (CentOS/RHEL)..."
                sudo yum install -y \
                    python3-devel \
                    python3-pip \
                    gcc \
                    openssl-devel \
                    libffi-devel \
                    pkgconfig
            elif command -v dnf &> /dev/null; then
                echo "📦 Installing system dependencies (Fedora)..."
                sudo dnf install -y \
                    python3-devel \
                    python3-pip \
                    gcc \
                    openssl-devel \
                    libffi-devel \
                    pkgconf-pkg-config
            else
                echo "⚠️  Please install python3-dev, build-essential, libffi-dev, and libssl-dev manually"
            fi
            ;;
        "Darwin")
            if command -v brew &> /dev/null; then
                echo "📦 Installing system dependencies (macOS)..."
                brew install python@3.12 pkg-config libffi openssl
            else
                echo "⚠️  Please install Homebrew and run: brew install python@3.12 pkg-config libffi openssl"
            fi
            ;;
        *)
            echo "⚠️  Unsupported OS. Please install build tools and Python development headers manually."
            ;;
    esac
}

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    echo "Installing Python 3..."
    install_system_deps
    exit 1
fi

# Get Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "🐍 Python version: $PYTHON_VERSION"

# Check minimum Python version (3.8+)
REQUIRED_VERSION="3.8"
if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo "✅ Python version is compatible"
else
    echo "❌ Python 3.8+ is required. Current version: $PYTHON_VERSION"
    exit 1
fi

# Install system dependencies
echo "🔧 Installing system dependencies..."
install_system_deps

# Upgrade pip to latest version
echo "📈 Upgrading pip..."
python3 -m pip install --upgrade pip setuptools wheel

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip, setuptools, and wheel in virtual environment
echo "📈 Upgrading build tools in virtual environment..."
pip install --upgrade pip setuptools wheel

# Install dependencies with better error handling
echo "📚 Installing Python dependencies..."
if ! pip install -r requirements.txt; then
    echo "❌ Failed to install some packages. Trying alternative approach..."
    echo "📚 Installing core packages first..."
    
    # Install core packages that usually work
    pip install Flask python-dotenv click
    
    # Install packages one by one to identify problematic ones
    while IFS= read -r line; do
        if [[ $line =~ ^[^#]*[^[:space:]] ]]; then
            package=$(echo "$line" | cut -d'=' -f1 | cut -d'>' -f1 | cut -d'<' -f1 | tr -d ' ')
            if [ ! -z "$package" ]; then
                echo "Installing $package..."
                pip install "$package" || echo "⚠️  Failed to install $package, skipping..."
            fi
        fi
    done < requirements.txt
fi

# Set up environment variables if .env doesn't exist
if [ ! -f ".env" ]; then
    echo "⚙️  Creating .env file..."
    cat > .env << EOF
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=dev-secret-key-$(date +%s)
JWT_SECRET_KEY=jwt-secret-key-$(date +%s)
DATABASE_URL=sqlite:///planventure.db
SQLALCHEMY_TRACK_MODIFICATIONS=False
JWT_ACCESS_TOKEN_EXPIRES=3600
EOF
fi

# Load environment variables
if [ -f ".env" ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Test Flask installation
echo "🧪 Testing Flask installation..."
if python -c "import flask; print(f'Flask {flask.__version__} installed successfully')" 2>/dev/null; then
    echo "✅ Flask is working"
else
    echo "❌ Flask installation failed"
    exit 1
fi

# Check if manage.py exists, if not create a basic one
if [ ! -f "manage.py" ]; then
    echo "📝 Creating basic manage.py..."
    cat > manage.py << 'EOF'
#!/usr/bin/env python3
import click
from flask.cli import with_appcontext
from app import create_app
from database import db, reset_database, create_tables
from models.user import User

app = create_app()

@click.command()
@click.option('--email', prompt='Email', help='User email')
@click.option('--password', prompt='Password', hide_input=True, help='User password')
@click.option('--first-name', prompt='First name', help='User first name')
@click.option('--last-name', prompt='Last name', help='User last name')
@with_appcontext
def create_user(email, password, first_name, last_name):
    """Create a new user"""
    try:
        user = User.create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        click.echo(f"✅ User created: {user.email}")
    except Exception as e:
        click.echo(f"❌ Error: {e}")

@click.command()
@with_appcontext
def init_db():
    """Initialize database"""
    create_tables(app)
    click.echo("✅ Database initialized")

@click.command()
@with_appcontext
def reset_db():
    """Reset database"""
    reset_database(app)
    click.echo("✅ Database reset")

@click.command()
@with_appcontext
def list_users():
    """List all users"""
    users = User.query.all()
    for user in users:
        click.echo(f"ID: {user.id}, Email: {user.email}, Name: {user.first_name} {user.last_name}")

@click.command()
@with_appcontext
def check_db():
    """Check database status"""
    try:
        db.session.execute('SELECT 1')
        users_count = User.query.count()
        click.echo(f"✅ Database connected. Users: {users_count}")
    except Exception as e:
        click.echo(f"❌ Database error: {e}")

if __name__ == '__main__':
    app.cli.add_command(create_user)
    app.cli.add_command(init_db)
    app.cli.add_command(reset_db)
    app.cli.add_command(list_users)
    app.cli.add_command(check_db)
    
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == 'init-db':
            with app.app_context():
                init_db()
        elif sys.argv[1] == 'check-db':
            with app.app_context():
                check_db()
        elif sys.argv[1] == 'list-users':
            with app.app_context():
                list_users()
        else:
            click.echo("Available commands: init-db, check-db, list-users, create-user")
    else:
        click.echo("Available commands: init-db, check-db, list-users, create-user")
EOF
    chmod +x manage.py
fi

# Initialize database
echo "🗄️  Initializing database..."
python manage.py init-db

# Check database status
echo "✅ Checking database status..."
python manage.py check-db

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "📋 Next steps:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Create a user: python manage.py create-user"
echo "  3. Run the app: python app.py"
echo ""
echo "🔧 Available commands:"
echo "  python manage.py init-db          # Initialize database"
echo "  python manage.py create-user      # Create a new user" 
echo "  python manage.py list-users       # List all users"
echo "  python manage.py check-db         # Check database status"
echo "  python app.py                     # Run the Flask app"
echo ""