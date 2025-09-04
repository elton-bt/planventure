import os
from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime, timezone
from sqlalchemy import text

# Local imports
from config import config
from database import init_db, create_tables
from routes.auth import auth_bp
from middleware import auth_middleware

def create_app(config_name=None):
    """Application factory"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    CORS(app, origins=app.config.get('CORS_ORIGINS', '*'))
    
    # Initialize database
    db = init_db(app)
    
    # Initialize middleware
    auth_middleware.init_app(app)
    
    # Create tables
    create_tables(app)
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    
    # Main routes
    @app.route('/')
    def home():
        """API home endpoint"""
        return jsonify({
            'message': 'Welcome to PlanVenture API',
            'version': '1.0.0',
            'status': 'active',
            'endpoints': {
                'auth': '/api/auth',
                'health': '/health',
                'docs': '/api/docs'
            },
            'available_auth_endpoints': {
                'register': 'POST /api/auth/register',
                'login': 'POST /api/auth/login',
                'logout': 'POST /api/auth/logout',
                'refresh': 'POST /api/auth/refresh',
                'profile': 'GET /api/auth/profile',
                'verify_email': 'POST /api/auth/verify-email',
                'forgot_password': 'POST /api/auth/forgot-password',
                'reset_password': 'POST /api/auth/reset-password',
                'change_password': 'POST /api/auth/change-password',
                'validate_token': 'POST /api/auth/validate-token'
            }
        })

    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        try:
            # Test database connection with proper text() wrapper
            from database import db
            db.session.execute(text('SELECT 1'))
            db_status = 'connected'
        except Exception as e:
            app.logger.error(f"Database health check failed: {str(e)}")
            db_status = 'disconnected'
        
        return jsonify({
            'status': 'healthy' if db_status == 'connected' else 'unhealthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'database': db_status,
            'environment': app.config.get('ENV', 'unknown'),
            'debug': app.config.get('DEBUG', False)
        })

    @app.route('/api/status')
    def api_status():
        """API status endpoint with more details"""
        try:
            from models.user import User
            from models.viagem import Viagem
            
            users_count = User.query.count()
            viagens_count = Viagem.query.count()
            
            return jsonify({
                'status': 'operational',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'database': {
                    'status': 'connected',
                    'users': users_count,
                    'trips': viagens_count
                },
                'version': '1.0.0',
                'environment': app.config.get('ENV', 'unknown')
            })
        except Exception as e:
            app.logger.error(f"Status check failed: {str(e)}")
            return jsonify({
                'status': 'error',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'database': {
                    'status': 'error',
                    'error': str(e)
                },
                'version': '1.0.0',
                'environment': app.config.get('ENV', 'unknown')
            }), 500

    # Global error handlers (middleware errors are handled automatically)
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            'success': False,
            'error': 'Bad request',
            'message': 'The request could not be understood by the server'
        }), 400

    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            'success': False,
            'error': 'Unauthorized',
            'message': 'Authentication required'
        }), 401

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            'success': False,
            'error': 'Forbidden',
            'message': 'Access denied'
        }), 403

    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({
            'success': False,
            'error': 'Not found',
            'message': 'The requested resource was not found'
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({
            'success': False,
            'error': 'Method not allowed',
            'message': 'The method is not allowed for the requested URL'
        }), 405

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {str(error)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'message': 'An unexpected error occurred'
        }), 500

    # Configure logging
    if not app.debug and not app.testing:
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        file_handler = RotatingFileHandler('logs/planventure.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('PlanVenture API startup')

    return app

# Create app instance
app = create_app()

if __name__ == '__main__':
    # Get configuration from environment
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() in ['true', '1', 'on']
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    
    print(f"🚀 Starting PlanVenture API...")
    print(f"📍 Environment: {os.environ.get('FLASK_ENV', 'development')}")
    print(f"🔧 Debug mode: {debug}")
    print(f"🌐 Server: http://{host}:{port}")
    print(f"📋 Health check: http://{host}:{port}/health")
    print(f"🔐 Auth endpoints: http://{host}:{port}/api/auth")
    print(f"🛡️ Middleware: Authentication, Rate Limiting, Validation")
    
    app.run(debug=debug, host=host, port=port)