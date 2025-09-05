"""
User model for PlanVenture API
Handles user authentication, profile management, and JWT tokens
"""
import os
from datetime import datetime, timezone, timedelta
import secrets
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app

from database import db

# Association (se houver outras relações futuras)
# ...

class PasswordUtils:
    @staticmethod
    def generate_salt():
        return secrets.token_hex(16)

    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        # Usamos werkzeug hashing + salt concatenado para consistência
        return generate_password_hash(password + salt)

    @staticmethod
    def verify(password: str, stored_hash: str, salt: str) -> bool:
        return check_password_hash(stored_hash, password + salt)


class JWTUtils:
    @staticmethod
    def _base_payload(user_id: int, exp_delta: timedelta, token_type: str):
        now = datetime.now(timezone.utc)
        return {
            "sub": str(user_id),
            "user_id": int(user_id),
            "type": token_type,  # garante claim de tipo
            "iat": int(now.timestamp()),
            "exp": int((now + exp_delta).timestamp()),
        }

    @staticmethod
    def generate_access_token(user_id: int, expires_minutes=60):
        secret = current_app.config.get("JWT_SECRET_KEY") or current_app.config.get("SECRET_KEY")
        payload = JWTUtils._base_payload(user_id, timedelta(minutes=expires_minutes), "access")
        return jwt.encode(payload, secret, algorithm="HS256")

    @staticmethod
    def generate_refresh_token(user_id: int, expires_days=30):
        secret = current_app.config.get("JWT_SECRET_KEY") or current_app.config.get("SECRET_KEY")
        payload = JWTUtils._base_payload(user_id, timedelta(days=expires_days), "refresh")
        return jwt.encode(payload, secret, algorithm="HS256")

    @staticmethod
    def generate_token(user_id: int, expires_minutes=60):
        # compatibilidade legada
        return JWTUtils.generate_access_token(user_id, expires_minutes=60)

    @staticmethod
    def verify_token(token: str, expected_type: str | None = None):
        secret = current_app.config.get("JWT_SECRET_KEY") or current_app.config.get("SECRET_KEY")
        try:
            payload = jwt.decode(token, secret, algorithms=["HS256"])
            # Compatibilidade: só valida tipo se claim existir
            if expected_type:
                claim_type = payload.get("type")
                if claim_type and claim_type != expected_type:
                    current_app.logger.warning(f"JWT type mismatch. Expected {expected_type}, got {claim_type}")
                    return None
            return payload
        except jwt.ExpiredSignatureError:
            current_app.logger.info("JWT expired")
            return None
        except jwt.InvalidTokenError as e:
            current_app.logger.warning(f"JWT invalid: {e}")
            return None

    @staticmethod
    def decode(token: str):
        # opcional manter (encaminha para verify_token sem checar tipo)
        return JWTUtils.verify_token(token)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(180), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    username = db.Column(db.String(80), unique=True)
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)

    password_hash = db.Column(db.String(255), nullable=False)
    password_salt = db.Column(db.String(64), nullable=False)

    # >>> ADICIONAR (faltava no modelo, já existe na tabela) <<<
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    # NOVO: controle de bloqueio (opcional)
    account_locked_until = db.Column(db.DateTime, nullable=True)

    # Campos para verificação de email (necessários para a rota de registro)
    email_verification_token = db.Column(db.String(128), nullable=True)
    email_verification_sent_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relação viagens (se existir tabela viagens)
    viagens = db.relationship("Viagem", backref="user", lazy="dynamic", cascade="all,delete-orphan")

    @property
    def full_name(self):
        return " ".join([p for p in [self.first_name, self.last_name] if p]) or None

    @property
    def is_account_locked(self):
        """
        Retorna True se a conta estiver bloqueada até um horário futuro.
        (Se não usar bloqueio ainda, sempre False quando campo nulo/passado.)
        """
        if self.account_locked_until and datetime.now(timezone.utc) < self.account_locked_until:
            return True
        return False

    # ---- Password handling ----
    def set_password(self, password: str):
        self.password_salt = PasswordUtils.generate_salt()
        self.password_hash = PasswordUtils.hash_password(password, self.password_salt)

    def check_password(self, password: str) -> bool:
        if not self.password_hash or not self.password_salt:
            return False
        return PasswordUtils.verify(password, self.password_hash, self.password_salt)

    def reset_login_failures(self):
        changed = False
        if self.failed_login_attempts != 0:
            self.failed_login_attempts = 0
            changed = True
        if self.account_locked_until:
            self.account_locked_until = None
            changed = True
        if changed:
            db.session.commit()

    def register_failed_login(self, max_attempts=5, lock_minutes=15):
        """
        Incrementa falhas e opcionalmente bloqueia.
        (Chame isto na lógica de autenticação se quiser ativar lockout.)
        """
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_attempts:
            self.account_locked_until = datetime.now(timezone.utc) + timedelta(minutes=lock_minutes)
            self.failed_login_attempts = 0  # zera contador ao bloquear
        db.session.commit()

    # ---- Token helpers ----
    def generate_tokens(self):
        return {
            "access_token": JWTUtils.generate_access_token(self.id),
            "refresh_token": JWTUtils.generate_refresh_token(self.id),
            "token_type": "Bearer",
            "expires_in": 3600,
        }

    # ---- Email verification helpers ----
    def generate_email_verification_token(self):
        """
        Gera e persiste um token de verificação de e-mail.
        (A rota de registro espera este método.)
        """
        token = secrets.token_urlsafe(32)
        self.email_verification_token = token
        self.email_verification_sent_at = datetime.now(timezone.utc)
        db.session.commit()
        return token

    def verify_email(self, token: str) -> bool:
        """
        Marca e-mail como verificado se o token confere.
        """
        if not self.email_verification_token:
            return False
        if self.email_verification_token != token:
            return False
        self.is_verified = True
        self.email_verification_token = None
        db.session.commit()
        return True

    # ---- Serialization ----
    def to_dict(self, include_security=False, include_timestamps=True):
        data = {
            "id": self.id,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "is_account_locked": self.is_account_locked,
        }
        if include_timestamps:
            data["created_at"] = self.created_at.isoformat() if self.created_at else None
            data["updated_at"] = self.updated_at.isoformat() if self.updated_at else None
        if include_security:
            data["has_password"] = bool(self.password_hash)
            data["failed_login_attempts"] = self.failed_login_attempts
            data["account_locked_until"] = (
                self.account_locked_until.isoformat() if self.account_locked_until else None
            )
        return data

    # ---- CRUD / Queries ----
    @staticmethod
    def find_by_email(email: str):
        return User.query.filter(db.func.lower(User.email) == email.lower()).first()

    @staticmethod
    def create_user(email: str, password: str, first_name=None, last_name=None, username=None):
        if User.find_by_email(email):
            raise ValueError("Email already registered")
        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            username=username,
            is_active=True,
            is_verified=True,  # opcional para desenvolvimento
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def authenticate(email: str, password: str):
        user = User.find_by_email(email)
        if not user:
            return {"success": False, "error": "Invalid credentials"}
        if not user.is_active:
            return {"success": False, "error": "User inactive"}
        if not user.check_password(password):
            return {"success": False, "error": "Invalid credentials"}
        tokens = user.generate_tokens()
        # Ajuste: embalar tokens em uma chave 'tokens' para compatibilidade com a rota de login
        return {
            "success": True,
            "user": user,
            "tokens": tokens
        }

    @staticmethod
    def get_user_from_token(token: str):
        """
        Valida access token e retorna usuário ou None.
        """
        payload = JWTUtils.verify_token(token, expected_type="access")
        if not payload:
            return None
        try:
            return User.query.get(int(payload.get("user_id") or payload.get("sub")))
        except Exception:
            return None