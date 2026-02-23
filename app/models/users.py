from app import db

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now())
    email = db.Column(db.String(120), unique=True, nullable=False)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    token_version = db.Column(db.Integer, default=0)  # For token invalidation
    otp_hash = db.Column(db.Text, nullable=True)
    otp_expires_at = db.Column(db.DateTime, nullable=True)
    otp_used = db.Column(db.Boolean, default=False)
    otp_verified = db.Column(db.Boolean, default=False)
    otp_attempts = db.Column(db.Integer, default=0)  # Track OTP verification attempts

    def __repr__(self):
        return f'<User {self.username}>'