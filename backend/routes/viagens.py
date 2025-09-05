"""
Travel routes for PlanVenture API
Handles trip management with authentication middleware
"""
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
from sqlalchemy import or_, and_

# Local imports
from models.viagem import Viagem
from models.user import User
from database import db
from middleware import (
    jwt_required, 
    verified_required, 
    rate_limited, 
    validate_json, 
    require_ownership,
    get_current_user
)

# Create blueprint for viagem routes
viagens_bp = Blueprint('viagens', __name__, url_prefix='/api/viagens')

# ==================== READ OPERATIONS ====================

@viagens_bp.route('/', methods=['GET'])
@jwt_required()
def list_user_trips(current_user):
    """
    List trips for authenticated user with optional filtering
    
    Query Parameters:
    - status: Filter by trip status
    - public_only: Show only public trips (true/false)
    - limit: Number of trips to return (default: 50, max: 100)
    - offset: Number of trips to skip (default: 0)
    - search: Search in destination or title
    """
    try:
        # Get query parameters
        status = request.args.get('status')
        public_only = request.args.get('public_only', '').lower() == 'true'
        limit = min(int(request.args.get('limit', 50)), 100)
        offset = int(request.args.get('offset', 0))
        search = request.args.get('search', '').strip()
        
        # Build query
        query = Viagem.query.filter_by(user_id=current_user.id)
        
        # Apply filters
        if status:
            query = query.filter_by(status=status)
        
        if public_only:
            query = query.filter_by(is_public=True)
        
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                or_(
                    Viagem.destino.ilike(search_pattern),
                    Viagem.titulo.ilike(search_pattern),
                    Viagem.descricao.ilike(search_pattern)
                )
            )
        
        # Apply pagination
        total = query.count()
        trips = query.order_by(Viagem.created_at.desc()).offset(offset).limit(limit).all()
        
        return jsonify({
            'success': True,
            'trips': [trip.to_dict() for trip in trips],
            'pagination': {
                'total': total,
                'limit': limit,
                'offset': offset,
                'has_more': offset + limit < total
            }
        }), 200
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': f'Invalid parameters: {str(e)}'
        }), 400
    except Exception as e:
        current_app.logger.error(f"List trips error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500

@viagens_bp.route('/<int:trip_id>', methods=['GET'])
@jwt_required()
@require_ownership(Viagem, 'trip_id', 'user_id')
def get_trip(current_user, trip_id, resource):
    """
    Get specific trip details (user must own the trip)
    
    Returns detailed trip information including itinerary
    """
    try:
        return jsonify({
            'success': True,
            'trip': resource.to_dict(include_user=True, include_itinerario=True)
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get trip error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500

@viagens_bp.route('/public', methods=['GET'])
@rate_limited(max_requests=100, window_minutes=15)
def list_public_trips():
    """
    List public trips (no authentication required)
    
    Query Parameters:
    - limit: Number of trips to return (default: 20, max: 50)
    - offset: Number of trips to skip (default: 0)
    - search: Search in destination or title
    - status: Filter by status
    """
    try:
        # Get query parameters
        limit = min(int(request.args.get('limit', 20)), 50)
        offset = int(request.args.get('offset', 0))
        search = request.args.get('search', '').strip()
        status = request.args.get('status')
        
        # Build query for public trips only
        query = Viagem.query.filter_by(is_public=True)
        
        # Apply filters
        if status:
            query = query.filter_by(status=status)
        
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                or_(
                    Viagem.destino.ilike(search_pattern),
                    Viagem.titulo.ilike(search_pattern)
                )
            )
        
        # Apply pagination
        total = query.count()
        trips = query.order_by(Viagem.created_at.desc()).offset(offset).limit(limit).all()
        
        return jsonify({
            'success': True,
            'trips': [trip.to_dict(include_user=True, include_itinerario=False) for trip in trips],
            'pagination': {
                'total': total,
                'limit': limit,
                'offset': offset,
                'has_more': offset + limit < total
            }
        }), 200
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': f'Invalid parameters: {str(e)}'
        }), 400
    except Exception as e:
        current_app.logger.error(f"List public trips error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500

# ==================== CREATE OPERATIONS ====================

@viagens_bp.route('/', methods=['POST'])
@jwt_required()
@rate_limited(max_requests=20, window_minutes=60)
@validate_json(
    required_fields=['destino', 'data_inicio', 'data_fim'],
    optional_fields={
        'titulo': None,
        'descricao': None,
        'latitude': None,
        'longitude': None,
        'budget': None,
        'status': 'planejando',
        'is_public': False,
        'itinerario': None
    }
)
def create_trip(data, current_user):
    """
    Create a new trip
    
    Expected JSON:
    {
        "destino": "Paris, France",
        "data_inicio": "2024-06-01",
        "data_fim": "2024-06-07",
        "titulo": "Vacation in Paris",
        "descricao": "Amazing trip to the city of lights",
        "latitude": 48.8566,
        "longitude": 2.3522,
        "budget": 2500.00,
        "status": "planejando",
        "is_public": false,
        "itinerario": [
            {
                "day": 1,
                "activities": ["Visit Eiffel Tower", "Seine River Cruise"],
                "accommodation": "Hotel Le Marais"
            }
        ]
    }
    """
    try:
        # Validate and parse dates
        try:
            data_inicio = datetime.strptime(data['data_inicio'], '%Y-%m-%d').date()
            data_fim = datetime.strptime(data['data_fim'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({
                'success': False,
                'error': 'Invalid date format. Use YYYY-MM-DD'
            }), 400
        
        # Validate dates logic
        today = datetime.now().date()
        if data_inicio < today:
            return jsonify({
                'success': False,
                'error': 'Start date cannot be in the past'
            }), 400
        
        if data_inicio > data_fim:
            return jsonify({
                'success': False,
                'error': 'Start date must be before end date'
            }), 400
        
        # Create trip
        trip = Viagem.create_viagem(
            user_id=current_user.id,
            destino=data['destino'],
            data_inicio=data_inicio,
            data_fim=data_fim,
            titulo=data.get('titulo'),
            descricao=data.get('descricao'),
            latitude=data.get('latitude'),
            longitude=data.get('longitude'),
            budget=data.get('budget'),
            status=data.get('status', 'planejando'),
            is_public=data.get('is_public', False),
            itinerario=data.get('itinerario')
        )
        
        current_app.logger.info(f"Trip created: {trip.id} by user {current_user.email}")
        
        return jsonify({
            'success': True,
            'message': 'Trip created successfully',
            'trip': trip.to_dict(include_itinerario=True)
        }), 201
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
    except Exception as e:
        current_app.logger.error(f"Create trip error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred while creating trip'
        }), 500

# ==================== UPDATE OPERATIONS ====================

@viagens_bp.route('/<int:trip_id>', methods=['PUT'])
@jwt_required()
@require_ownership(Viagem, 'trip_id', 'user_id')
@validate_json(required_fields=[])
def update_trip(data, current_user, trip_id, resource):
    """
    Update trip (user must own the trip)
    
    All fields are optional for updates.
    Only provided fields will be updated.
    """
    try:
        # Parse dates if provided
        if 'data_inicio' in data and data['data_inicio']:
            try:
                data['data_inicio'] = datetime.strptime(data['data_inicio'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({
                    'success': False,
                    'error': 'Invalid start date format. Use YYYY-MM-DD'
                }), 400
        
        if 'data_fim' in data and data['data_fim']:
            try:
                data['data_fim'] = datetime.strptime(data['data_fim'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({
                    'success': False,
                    'error': 'Invalid end date format. Use YYYY-MM-DD'
                }), 400
        
        # Validate status if provided
        if 'status' in data:
            valid_statuses = ['planejando', 'confirmada', 'em_andamento', 'concluida', 'cancelada']
            if data['status'] not in valid_statuses:
                return jsonify({
                    'success': False,
                    'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'
                }), 400
        
        # Update trip
        updated_trip = resource.update_viagem(**data)
        
        current_app.logger.info(f"Trip updated: {trip_id} by user {current_user.email}")
        
        return jsonify({
            'success': True,
            'message': 'Trip updated successfully',
            'trip': updated_trip.to_dict(include_itinerario=True)
        }), 200
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
    except Exception as e:
        current_app.logger.error(f"Update trip error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred while updating trip'
        }), 500

@viagens_bp.route('/<int:trip_id>/status', methods=['PATCH'])
@jwt_required()
@require_ownership(Viagem, 'trip_id', 'user_id')
@validate_json(required_fields=['status'])
def update_trip_status(data, current_user, trip_id, resource):
    """
    Update only the trip status
    
    Expected JSON:
    {
        "status": "confirmada"
    }
    """
    try:
        status = data['status']
        valid_statuses = ['planejando', 'confirmada', 'em_andamento', 'concluida', 'cancelada']
        
        if status not in valid_statuses:
            return jsonify({
                'success': False,
                'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'
            }), 400
        
        # Update only status
        updated_trip = resource.update_viagem(status=status)
        
        current_app.logger.info(f"Trip status updated: {trip_id} -> {status} by user {current_user.email}")
        
        return jsonify({
            'success': True,
            'message': f'Trip status updated to {status}',
            'trip': {
                'id': updated_trip.id,
                'status': updated_trip.status,
                'updated_at': updated_trip.updated_at.isoformat()
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Update trip status error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred while updating trip status'
        }), 500

@viagens_bp.route('/<int:trip_id>/itinerary', methods=['PUT'])
@jwt_required()
@require_ownership(Viagem, 'trip_id', 'user_id')
@validate_json(required_fields=['itinerario'])
def update_trip_itinerary(data, current_user, trip_id, resource):
    """
    Update only the trip itinerary
    
    Expected JSON:
    {
        "itinerario": [
            {
                "day": 1,
                "date": "2024-06-01",
                "activities": ["Activity 1", "Activity 2"],
                "accommodation": "Hotel Name",
                "notes": "Special notes"
            }
        ]
    }
    """
    try:
        # Update only itinerary
        updated_trip = resource.update_viagem(itinerario=data['itinerario'])
        
        current_app.logger.info(f"Trip itinerary updated: {trip_id} by user {current_user.email}")
        
        return jsonify({
            'success': True,
            'message': 'Trip itinerary updated successfully',
            'itinerario': updated_trip.get_itinerario()
        }), 200
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
    except Exception as e:
        current_app.logger.error(f"Update trip itinerary error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred while updating itinerary'
        }), 500

# ==================== DELETE OPERATIONS ====================

@viagens_bp.route('/<int:trip_id>', methods=['DELETE'])
@jwt_required()
@require_ownership(Viagem, 'trip_id', 'user_id')
def delete_trip(current_user, trip_id, resource):
    """
    Delete trip (user must own the trip)
    
    This action is irreversible.
    """
    try:
        trip_title = resource.titulo or resource.destino
        resource.delete_viagem()
        
        current_app.logger.info(f"Trip deleted: {trip_id} ({trip_title}) by user {current_user.email}")
        
        return jsonify({
            'success': True,
            'message': f'Trip "{trip_title}" deleted successfully'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Delete trip error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred while deleting trip'
        }), 500

# ==================== SEARCH AND FILTER OPERATIONS ====================

@viagens_bp.route('/search', methods=['GET'])
@jwt_required()
def search_trips(current_user):
    """
    Advanced search for user's trips
    
    Query Parameters:
    - q: Search query (searches in destination, title, description)
    - status: Filter by status
    - min_budget: Minimum budget
    - max_budget: Maximum budget
    - date_from: Start date range (YYYY-MM-DD)
    - date_to: End date range (YYYY-MM-DD)
    - has_coordinates: Filter trips with coordinates (true/false)
    - limit: Number of results (default: 20, max: 50)
    - offset: Offset for pagination
    """
    try:
        # Get search parameters
        query_text = request.args.get('q', '').strip()
        status = request.args.get('status')
        min_budget = request.args.get('min_budget', type=float)
        max_budget = request.args.get('max_budget', type=float)
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        has_coordinates = request.args.get('has_coordinates', '').lower() == 'true'
        limit = min(int(request.args.get('limit', 20)), 50)
        offset = int(request.args.get('offset', 0))
        
        # Build base query
        query = Viagem.query.filter_by(user_id=current_user.id)
        
        # Apply text search
        if query_text:
            search_pattern = f'%{query_text}%'
            query = query.filter(
                or_(
                    Viagem.destino.ilike(search_pattern),
                    Viagem.titulo.ilike(search_pattern),
                    Viagem.descricao.ilike(search_pattern)
                )
            )
        
        # Apply filters
        if status:
            query = query.filter_by(status=status)
        
        if min_budget is not None:
            query = query.filter(Viagem.budget >= min_budget)
        
        if max_budget is not None:
            query = query.filter(Viagem.budget <= max_budget)
        
        if date_from:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            query = query.filter(Viagem.data_inicio >= date_from_obj)
        
        if date_to:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            query = query.filter(Viagem.data_fim <= date_to_obj)
        
        if has_coordinates:
            query = query.filter(
                and_(
                    Viagem.latitude.isnot(None),
                    Viagem.longitude.isnot(None)
                )
            )
        
        # Apply pagination and ordering
        total = query.count()
        trips = query.order_by(Viagem.created_at.desc()).offset(offset).limit(limit).all()
        
        return jsonify({
            'success': True,
            'trips': [trip.to_dict() for trip in trips],
            'search_params': {
                'query': query_text,
                'status': status,
                'min_budget': min_budget,
                'max_budget': max_budget,
                'date_from': date_from,
                'date_to': date_to,
                'has_coordinates': has_coordinates
            },
            'pagination': {
                'total': total,
                'limit': limit,
                'offset': offset,
                'has_more': offset + limit < total
            }
        }), 200
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': f'Invalid search parameters: {str(e)}'
        }), 400
    except Exception as e:
        current_app.logger.error(f"Search trips error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred during search'
        }), 500

@viagens_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_user_trip_stats(current_user):
    """
    Get statistics about user's trips
    """
    try:
        trips = Viagem.find_by_user(current_user.id)
        
        # Calculate statistics
        total_trips = len(trips)
        
        # Status distribution
        status_counts = {}
        for trip in trips:
            status_counts[trip.status] = status_counts.get(trip.status, 0) + 1
        
        # Budget statistics
        budgets = [trip.budget for trip in trips if trip.budget is not None]
        budget_stats = {
            'total_budget': sum(budgets) if budgets else 0,
            'average_budget': sum(budgets) / len(budgets) if budgets else 0,
            'min_budget': min(budgets) if budgets else 0,
            'max_budget': max(budgets) if budgets else 0,
            'trips_with_budget': len(budgets)
        }
        
        # Duration statistics
        durations = [trip.duracao_dias for trip in trips]
        duration_stats = {
            'total_days': sum(durations),
            'average_duration': sum(durations) / len(durations) if durations else 0,
            'min_duration': min(durations) if durations else 0,
            'max_duration': max(durations) if durations else 0
        }
        
        # Other statistics
        public_trips = len([trip for trip in trips if trip.is_public])
        trips_with_coordinates = len([trip for trip in trips if trip.coordenadas])
        
        return jsonify({
            'success': True,
            'stats': {
                'total_trips': total_trips,
                'public_trips': public_trips,
                'trips_with_coordinates': trips_with_coordinates,
                'status_distribution': status_counts,
                'budget_stats': budget_stats,
                'duration_stats': duration_stats
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get trip stats error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred while calculating statistics'
        }), 500

# ==================== ERROR HANDLERS ====================

@viagens_bp.errorhandler(400)
def bad_request(error):
    return jsonify({
        'success': False,
        'error': 'Bad request',
        'message': 'Invalid request data'
    }), 400

@viagens_bp.errorhandler(401)
def unauthorized(error):
    return jsonify({
        'success': False,
        'error': 'Unauthorized',
        'message': 'Authentication required'
    }), 401

@viagens_bp.errorhandler(403)
def forbidden(error):
    return jsonify({
        'success': False,
        'error': 'Forbidden',
        'message': 'Access denied'
    }), 403

@viagens_bp.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Not found',
        'message': 'Trip not found'
    }), 404

@viagens_bp.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'success': False,
        'error': 'Method not allowed',
        'message': 'HTTP method not allowed for this endpoint'
    }), 405