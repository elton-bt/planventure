"""
Travel routes for PlanVenture API
Handles trip management with authentication middleware
"""
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime

# Local imports
from models.viagem import Viagem
from models.user import User
from database import db
from middleware import (
    jwt_required, 
    verified_required, 
    rate_limited, 
    validate_json, 
    require_ownership
)

# Create blueprint for viagem routes
viagens_bp = Blueprint('viagens', __name__, url_prefix='/api/viagens')

@viagens_bp.route('/', methods=['GET'])
@jwt_required()
def list_user_trips(current_user):
    """List trips for authenticated user"""
    try:
        trips = Viagem.find_by_user(current_user.id)
        
        return jsonify({
            'success': True,
            'trips': [trip.to_dict() for trip in trips],
            'total': len(trips)
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"List trips error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500

@viagens_bp.route('/', methods=['POST'])
@jwt_required()
@rate_limited(max_requests=20, window_minutes=60)  # Limit trip creation
@validate_json(
    required_fields=['destino', 'data_inicio', 'data_fim'],
    optional_fields={
        'titulo': None,
        'descricao': None,
        'latitude': None,
        'longitude': None,
        'budget': None,
        'is_public': False
    }
)
def create_trip(data, current_user):
    """Create a new trip"""
    try:
        # Parse dates
        data_inicio = datetime.strptime(data['data_inicio'], '%Y-%m-%d').date()
        data_fim = datetime.strptime(data['data_fim'], '%Y-%m-%d').date()
        
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
            is_public=data.get('is_public', False)
        )
        
        current_app.logger.info(f"Trip created: {trip.id} by user {current_user.email}")
        
        return jsonify({
            'success': True,
            'message': 'Trip created successfully',
            'trip': trip.to_dict()
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
            'error': 'An unexpected error occurred'
        }), 500

@viagens_bp.route('/<int:trip_id>', methods=['GET'])
@jwt_required()
@require_ownership(Viagem, 'trip_id', 'user_id')
def get_trip(current_user, trip_id, resource):
    """Get specific trip (user must own the trip)"""
    try:
        return jsonify({
            'success': True,
            'trip': resource.to_dict(include_user=True)
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get trip error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500

@viagens_bp.route('/<int:trip_id>', methods=['PUT'])
@jwt_required()
@require_ownership(Viagem, 'trip_id', 'user_id')
@validate_json(required_fields=[])
def update_trip(data, current_user, trip_id, resource):
    """Update trip (user must own the trip)"""
    try:
        # Parse dates if provided
        if 'data_inicio' in data and data['data_inicio']:
            data['data_inicio'] = datetime.strptime(data['data_inicio'], '%Y-%m-%d').date()
        
        if 'data_fim' in data and data['data_fim']:
            data['data_fim'] = datetime.strptime(data['data_fim'], '%Y-%m-%d').date()
        
        # Update trip
        updated_trip = resource.update_viagem(**data)
        
        current_app.logger.info(f"Trip updated: {trip_id} by user {current_user.email}")
        
        return jsonify({
            'success': True,
            'message': 'Trip updated successfully',
            'trip': updated_trip.to_dict()
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
            'error': 'An unexpected error occurred'
        }), 500

@viagens_bp.route('/<int:trip_id>', methods=['DELETE'])
@jwt_required()
@require_ownership(Viagem, 'trip_id', 'user_id')
def delete_trip(current_user, trip_id, resource):
    """Delete trip (user must own the trip)"""
    try:
        resource.delete_viagem()
        
        current_app.logger.info(f"Trip deleted: {trip_id} by user {current_user.email}")
        
        return jsonify({
            'success': True,
            'message': 'Trip deleted successfully'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Delete trip error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500

@viagens_bp.route('/public', methods=['GET'])
@rate_limited(max_requests=100, window_minutes=15)  # Rate limit for public endpoint
def list_public_trips():
    """List public trips (no authentication required)"""
    try:
        trips = Viagem.find_public_trips()
        
        return jsonify({
            'success': True,
            'trips': [trip.to_dict(include_user=True) for trip in trips],
            'total': len(trips)
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"List public trips error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred'
        }), 500