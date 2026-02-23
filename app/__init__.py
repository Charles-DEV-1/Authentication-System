from app.database import init_db, db
from flask import Flask
from datetime import timedelta
from flask_mail import Mail
from flask_jwt_extended import JWTManager
import redis
import dotenv
import os

# Initialize Redis client for token revocation
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
jwt = JWTManager()
mail = Mail()

#===== Token Revocation Logic =====
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    user_id = jwt_payload['sub']
    token_version = jwt_payload.get('token_version', 0)  # Get token version from JWT claims
    from app.models.users import User
    user = User.query.get(user_id)
    if user and user.token_version != token_version:
        return True  # Token is revoked if token version doesn't match
    token = redis_client.get(f"revoked:{jti}")  # Implement this function to check if the jti is in your blocklist (e.g., Redis)
    return token is not None  # Return True if the token is revoked, False otherwise    

#===== Application Factory =====
def create_app():
    app = Flask(__name__)
    dotenv.load_dotenv()
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_TOKEN_LOCATION'] = ["cookies"]   # ← THIS is the missing piece
    app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_token'  # 👈 Match YOUR cookie name
    app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'    # 👈 Match YOUR cookie name
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['JWT_COOKIE_SECURE'] = False  # (True only when using HTTPS)
    app.config['JWT_COOKIE_HTTPONLY'] = True
    app.config['JWT_COOKIE_SAMESITE'] = "Lax"

    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

    # Initialize extensions


    # Needed for refresh protection
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False

    print(os.getenv("JWT_SECRET_KEY"))   
    
    jwt.init_app(app)
    mail.init_app(app)
    init_db(app)
    
    

   

    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    return app

