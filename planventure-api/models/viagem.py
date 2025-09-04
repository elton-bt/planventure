from datetime import datetime, timezone
from sqlalchemy import text
import json

# Import db from database module
from database import db

class Viagem(db.Model):
    __tablename__ = 'viagens'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign key to User
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Trip information
    destino = db.Column(db.String(200), nullable=False)
    data_inicio = db.Column(db.Date, nullable=False)
    data_fim = db.Column(db.Date, nullable=False)
    
    # Coordinates (latitude and longitude)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    
    # Itinerary stored as JSON
    itinerario = db.Column(db.Text, nullable=True)  # JSON string
    
    # Trip details
    titulo = db.Column(db.String(150), nullable=True)
    descricao = db.Column(db.Text, nullable=True)
    budget = db.Column(db.Float, nullable=True)
    status = db.Column(db.String(20), default='planejando', nullable=False)  # planejando, confirmada, em_andamento, concluida, cancelada
    
    # Privacy settings
    is_public = db.Column(db.Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationship with User
    user = db.relationship('User', backref=db.backref('viagens', lazy=True, cascade='all, delete-orphan'))
    
    def __init__(self, user_id, destino, data_inicio, data_fim, **kwargs):
        self.user_id = user_id
        self.destino = destino
        self.data_inicio = data_inicio
        self.data_fim = data_fim
        
        # Optional fields
        self.titulo = kwargs.get('titulo')
        self.descricao = kwargs.get('descricao')
        self.latitude = kwargs.get('latitude')
        self.longitude = kwargs.get('longitude')
        self.budget = kwargs.get('budget')
        self.status = kwargs.get('status', 'planejando')
        self.is_public = kwargs.get('is_public', False)
        
        # Handle itinerary
        itinerario = kwargs.get('itinerario')
        if itinerario:
            self.set_itinerario(itinerario)
    
    def __repr__(self):
        return f'<Viagem {self.titulo or self.destino} - {self.user.email if self.user else "Unknown"}>'
    
    def set_itinerario(self, itinerario_data):
        """Set itinerary data (converts dict/list to JSON string)"""
        if isinstance(itinerario_data, (dict, list)):
            self.itinerario = json.dumps(itinerario_data, ensure_ascii=False)
        elif isinstance(itinerario_data, str):
            # Validate JSON string
            try:
                json.loads(itinerario_data)
                self.itinerario = itinerario_data
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON format for itinerary")
        else:
            raise ValueError("Itinerary must be a dict, list, or valid JSON string")
    
    def get_itinerario(self):
        """Get itinerary data as Python object"""
        if self.itinerario:
            try:
                return json.loads(self.itinerario)
            except json.JSONDecodeError:
                return None
        return None
    
    @property
    def duracao_dias(self):
        """Calculate trip duration in days"""
        if self.data_inicio and self.data_fim:
            return (self.data_fim - self.data_inicio).days + 1
        return 0
    
    @property
    def coordenadas(self):
        """Get coordinates as a tuple"""
        if self.latitude is not None and self.longitude is not None:
            return (self.latitude, self.longitude)
        return None
    
    def set_coordenadas(self, latitude, longitude):
        """Set coordinates"""
        self.latitude = float(latitude) if latitude is not None else None
        self.longitude = float(longitude) if longitude is not None else None
    
    def to_dict(self, include_user=False, include_itinerario=True):
        """Convert trip to dictionary"""
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'destino': self.destino,
            'titulo': self.titulo,
            'descricao': self.descricao,
            'data_inicio': self.data_inicio.isoformat() if self.data_inicio else None,
            'data_fim': self.data_fim.isoformat() if self.data_fim else None,
            'duracao_dias': self.duracao_dias,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'coordenadas': self.coordenadas,
            'budget': self.budget,
            'status': self.status,
            'is_public': self.is_public,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_itinerario:
            data['itinerario'] = self.get_itinerario()
        
        if include_user and self.user:
            data['user'] = self.user.to_dict(include_timestamps=False)
        
        return data
    
    def to_json(self):
        """Convert to JSON-serializable dict"""
        return self.to_dict()
    
    @classmethod
    def find_by_user(cls, user_id):
        """Find all trips by user ID"""
        return cls.query.filter_by(user_id=user_id).all()
    
    @classmethod
    def find_public_trips(cls):
        """Find all public trips"""
        return cls.query.filter_by(is_public=True).all()
    
    @classmethod
    def find_by_destination(cls, destino, user_id=None):
        """Find trips by destination"""
        query = cls.query.filter(cls.destino.ilike(f'%{destino}%'))
        if user_id:
            query = query.filter_by(user_id=user_id)
        return query.all()
    
    @classmethod
    def find_by_status(cls, status, user_id=None):
        """Find trips by status"""
        query = cls.query.filter_by(status=status)
        if user_id:
            query = query.filter_by(user_id=user_id)
        return query.all()
    
    @classmethod
    def create_viagem(cls, user_id, destino, data_inicio, data_fim, **kwargs):
        """Create new trip with validation"""
        from models.user import User
        
        # Validate user exists
        user = User.query.get(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Validate dates
        if data_inicio > data_fim:
            raise ValueError("Start date must be before end date")
        
        # Validate coordinates if provided
        latitude = kwargs.get('latitude')
        longitude = kwargs.get('longitude')
        if latitude is not None and longitude is not None:
            try:
                latitude = float(latitude)
                longitude = float(longitude)
                if not (-90 <= latitude <= 90):
                    raise ValueError("Latitude must be between -90 and 90")
                if not (-180 <= longitude <= 180):
                    raise ValueError("Longitude must be between -180 and 180")
                kwargs['latitude'] = latitude
                kwargs['longitude'] = longitude
            except (ValueError, TypeError):
                raise ValueError("Invalid coordinates format")
        
        # Validate status
        valid_statuses = ['planejando', 'confirmada', 'em_andamento', 'concluida', 'cancelada']
        status = kwargs.get('status', 'planejando')
        if status not in valid_statuses:
            raise ValueError(f"Status must be one of: {', '.join(valid_statuses)}")
        
        # Validate budget
        budget = kwargs.get('budget')
        if budget is not None:
            try:
                kwargs['budget'] = float(budget)
                if kwargs['budget'] < 0:
                    raise ValueError("Budget must be positive")
            except (ValueError, TypeError):
                raise ValueError("Invalid budget format")
        
        # Create trip
        viagem = cls(
            user_id=user_id,
            destino=destino,
            data_inicio=data_inicio,
            data_fim=data_fim,
            **kwargs
        )
        
        db.session.add(viagem)
        db.session.commit()
        
        return viagem
    
    def update_viagem(self, **kwargs):
        """Update trip with validation"""
        # Update allowed fields
        allowed_fields = [
            'destino', 'titulo', 'descricao', 'data_inicio', 'data_fim',
            'latitude', 'longitude', 'budget', 'status', 'is_public'
        ]
        
        for field, value in kwargs.items():
            if field in allowed_fields and hasattr(self, field):
                if field in ['data_inicio', 'data_fim'] and value:
                    # Validate dates
                    if field == 'data_inicio' and self.data_fim and value > self.data_fim:
                        raise ValueError("Start date must be before end date")
                    if field == 'data_fim' and self.data_inicio and value < self.data_inicio:
                        raise ValueError("End date must be after start date")
                
                setattr(self, field, value)
        
        # Handle itinerary separately
        if 'itinerario' in kwargs:
            self.set_itinerario(kwargs['itinerario'])
        
        # Handle coordinates
        if 'coordenadas' in kwargs:
            coords = kwargs['coordenadas']
            if isinstance(coords, (list, tuple)) and len(coords) == 2:
                self.set_coordenadas(coords[0], coords[1])
        
        self.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        
        return self
    
    def delete_viagem(self):
        """Delete trip"""
        db.session.delete(self)
        db.session.commit()