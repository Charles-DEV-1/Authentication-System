from flask import Blueprint, Flask, render_template, request, jsonify, make_response
import redis
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import hmac
import os
from app import redis_client, mail
from flask_mail import Message
import time
from datetime import timedelta, datetime
from app import db
from app.models.users import User
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    set_access_cookies,
    set_refresh_cookies,
    jwt_required,
    get_jwt_identity,
    get_jwt
)

auth_bp = Blueprint('auth', __name__, template_folder='routes')

@auth_bp.route('/', methods= ['GET'])
def home():
    return jsonify({'Message':'The connection was successful'})
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')  # Make sure to get email too since it's required

    if not username or not password or not email:
        return jsonify({'message': 'Username, password, and email are required'}), 400

    # Check if user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'User already exists'}), 400

    # Hash the password
    hashed_password = generate_password_hash(password)

    # Create new user
    new_user = User(
        username=username,
        password_hash=hashed_password,
        email=email
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        # Update last login time
        user.last_login = db.func.now()
        user.token_version = 0  # Ensure token version is included in JWT claims
        db.session.commit()
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id), additional_claims={"token_version": user.token_version})
        response = make_response(jsonify({'message': 'Login successful'}), 200)
        
        response.set_cookie('access_token', access_token, httponly=True, secure=False, samesite='Lax', max_age=900)
        response.set_cookie('refresh_token', refresh_token, httponly=True, secure=False, samesite='Lax', max_age=604800)
    else:
        response = make_response(jsonify({'message': 'Invalid username or password'}), 401)


    return response


@auth_bp.route("/me", methods=['GET'])
@jwt_required()
def get_current_user():
    current_user_id = int(get_jwt_identity())
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'last_login': user.last_login
    }), 200

@auth_bp.route("/refresh", methods= ["POST"])
@jwt_required(refresh=True)
def refresh():
    user_id = int(get_jwt_identity())

    access_token = create_access_token(identity=str(user_id))
    response = make_response(jsonify({'message': 'Token refreshed'}), 200)
    response.set_cookie('access_token', access_token, httponly=True, secure=False, samesite='Lax', max_age=900)
    user = User.query.get(user_id)
    if user:
        user.token_version = 0  # Ensure token version is included in JWT claims
        db.session.commit()
    return response



@auth_bp.route("/logout", methods=['POST'])
@jwt_required(refresh=True)
def logout():
    jti = get_jwt()['jti']
    exp = get_jwt()['exp']
    TimeToLive = exp - int(time.time()) # Calculate remaining time until token expiration
    if TimeToLive > 0:
        redis_client.set(f"revoked:{jti}", "true", ex=TimeToLive)  # Set the revoked token in Redis with an expiration time
    response = make_response(jsonify({'message': 'Logout successful'}), 200)
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
    return response

@auth_bp.route("/logout_all", methods=['POST'])    
@jwt_required(refresh = True)
def logout_all():
    current_user_id = int(get_jwt()['sub']) # Get the user ID from the JWT identity
    # Increment token version for the user
    user = User.query.get(current_user_id)
    if user:
        user.token_version += 1
        db.session.commit()
    response = make_response(jsonify({'message': 'Logged out of all sessions'}), 200)
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
    return response

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

@auth_bp.route("/forgot-password", methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': "If the email exists, an OTP has been sent."}), 404

    # Generate a random 6-digit OTP
    otp = str(secrets.randbelow(1000000)).zfill(6)
    
    # Hash the OTP
    hashed_otp = hash_otp(otp)
    
    # Update user with OTP and expiration time (10 minutes from now)
    user.otp_hash = hashed_otp
    user.otp_expires_at = datetime.utcnow() + timedelta(minutes=10)
    user.otp_used = False
    user.otp_verified = False
    db.session.commit()
    # Send OTP to user's email
    msg = Message(
    subject="Your Password Reset OTP",
    recipients=[user.email]
    )
    msg.body = f"""
    Hello,

    You requested to reset your password.

    Your OTP is: {otp}

    This code will expire in 10 minutes.

    If you did not request this, ignore this email.
    """
    mail.send(msg)
    return jsonify({
        'message': 'OTP sent to your email',
        'otp': otp  # For testing purposes, include the OTP in the response (remove in production)
    }), 200

@auth_bp.route("/check-otp", methods=['POST'])
def check_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({'message': 'Email and OTP are required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': "OTP sent if the email exists"}), 404

    if user.otp_used:
        return jsonify({'message': 'OTP has already been used'}), 400

    if not user.otp_hash or not user.otp_expires_at:
        return jsonify({'message': 'No OTP request found'}), 400    

    if datetime.utcnow() > user.otp_expires_at:
        return jsonify({'message': 'OTP has expired'}), 400

    if user.otp_attempts >= 5:
        return jsonify({'message': 'Too many attempts. Try again later.'}), 429    

    compared_otp = hmac.compare_digest(hash_otp(otp), user.otp_hash)    
    if not compared_otp:
        user.otp_attempts += 1
        db.session.commit()
        return jsonify({'message': 'Invalid OTP'}), 400

    # Mark OTP as verified and used
    user.otp_verified = True
    user.otp_used = True
    user.otp_attempts = 0  # Reset attempts on successful verification
    db.session.commit()

    return jsonify({'message': 'OTP is valid'}), 200

@auth_bp.route("/reset-password", methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User with this email does not exist'}), 404
    if not user.otp_verified or not user.otp_used or datetime.utcnow() > user.otp_expires_at:
        return jsonify({'message': 'OTP verification required'}), 400
    new_password = data.get('new_password')            
    if not new_password:
        return jsonify({'message': 'New password is required'}), 400
    user.password_hash = generate_password_hash(new_password)
    user.otp_verified = False  # Reset OTP verification status
    user.token_version += 1  # Invalidate existing tokens
    user.otp_hash = None  # Clear OTP hash
    user.otp_expires_at = None  # Clear OTP expiration
    user.otp_used = False  # Reset OTP used 
    user.otp_attempts = 0  # Reset OTP attempts

    db.session.commit()
    return jsonify({'message': 'Password reset successfully'}), 200