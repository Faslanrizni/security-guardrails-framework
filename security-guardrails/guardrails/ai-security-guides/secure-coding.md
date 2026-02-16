#  Secure Coding Guidelines for AI-Assisted Development

## Why This Matters
AI models are trained on public code, which often contains **bad security practices**. 
These guidelines ensure AI-generated code meets enterprise security standards.

##  Authentication & Session Management

###  DO THIS - Secure Authentication
```python
from flask import session, request
from datetime import timedelta
import bcrypt
import rate_limit

# Secure session configuration
app.config['SESSION_COOKIE_SECURE'] = True      # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True    # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

@app.route('/login', methods=['POST'])
@rate_limit.limit("5 per minute")  # Prevent brute force
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # Get user from database (parameterized query)
        user = db.execute(
            "SELECT * FROM users WHERE username = %s",
            (username,)
        ).fetchone()
        
        if user and bcrypt.check_password_hash(user.password_hash, password):
            # Regenerate session ID to prevent fixation
            session.regenerate()
            
            # Set session data
            session['user_id'] = user.id
            session['role'] = user.role
            session.permanent = True
            
            # Log success
            app.logger.info(f"Login success - User: {user.id}, IP: {request.remote_addr}")
            
            return {"status": "success", "user": user.id}
        
        # Log failure
        app.logger.warning(f"Login failed - Username: {username}, IP: {request.remote_addr}")
        return {"error": "Invalid credentials"}, 401
        
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return {"error": "Internal error"}, 500



##  Input Validation

### DO THIS - Comprehensive Validation
```python
from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional
import re

class UserInput(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    age: int = Field(..., ge=18, le=120)
    phone: Optional[str] = None
    
    @validator('username')
    def validate_username(cls, v):
        # Only allow alphanumeric and underscore
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username can only contain letters, numbers, and underscore')
        return v
    
    @validator('phone')
    def validate_phone(cls, v):
        if v:
            # Validate phone format (simple example)
            if not re.match(r'^\+?[0-9]{10,15}$', v):
                raise ValueError('Invalid phone format')
        return v

@app.route('/user', methods=['POST'])
def create_user():
    try:
        # Auto-validates input
        data = UserInput(**request.json)
        
        # Process validated data
        db.execute(
            "INSERT INTO users (username, email, age) VALUES (%s, %s, %s)",
            (data.username, data.email, data.age)
        )
        
        return {"status": "created", "username": data.username}
        
    except ValueError as e:
        return {"error": str(e)}, 400
    except Exception as e:
        app.logger.error(f"User creation error: {str(e)}")
        return {"error": "Internal error"}, 500





### **3. Add Error Handling Section**


import logging
import traceback
from flask import jsonify

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/data/<int:id>')
def get_data(id):
    try:
        data = db.execute(
            "SELECT * FROM items WHERE id = %s",
            (id,)
        ).fetchone()
        
        if not data:
            return jsonify({"error": "Item not found"}), 404
        
        # Remove sensitive fields
        safe_data = {
            'id': data.id,
            'name': data.name,
            'created_at': data.created_at.isoformat()
        }
        return jsonify(safe_data)
        
    except DatabaseError as e:
        # Log full details internally
        logger.error(f"Database error for id {id}: {str(e)}")
        logger.debug(traceback.format_exc())
        
        # Return generic message to user
        return jsonify({"error": "Database error occurred"}), 500
        
    except Exception as e:
        logger.critical(f"Unexpected error: {str(e)}")
        logger.debug(traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500




### **4. Add Cryptography Section**


from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import bcrypt
import base64
import os

# For password hashing (always use bcrypt)
def hash_password(password: str) -> str:
    """Hash password with bcrypt (cost factor 12)"""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# For data encryption
def encrypt_data(data: bytes, key: bytes = None) -> dict:
    """Encrypt data using Fernet (AES-128)"""
    if key is None:
        key = Fernet.generate_key()
    
    cipher = Fernet(key)
    encrypted = cipher.encrypt(data)
    
    return {
        'encrypted': base64.b64encode(encrypted).decode('utf-8'),
        'key': base64.b64encode(key).decode('utf-8')  # Store securely!
    }

def decrypt_data(encrypted_data: str, key: str) -> bytes:
    """Decrypt data using Fernet"""
    cipher = Fernet(base64.b64decode(key))
    return cipher.decrypt(base64.b64decode(encrypted_data))

# For key derivation (when using passwords)
def derive_key(password: str, salt: bytes = None) -> tuple:
    """Derive encryption key from password"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt





### **5. Add SQL Injection Prevention Section**


## SQL Injection Prevention

###  DO THIS - Parameterized Queries

# PostgreSQL/MySQL with psycopg2
def get_user(email):
    cursor.execute(
        "SELECT * FROM users WHERE email = %s",
        (email,)
    )
    return cursor.fetchone()

# With SQLAlchemy ORM
def get_user(email):
    return User.query.filter_by(email=email).first()

# With Django ORM
def get_user(email):
    return User.objects.filter(email=email).first()





### **6. Add Security Headers Section**
##  Security Headers
###  DO THIS - Add Security Headers

from flask import Flask, jsonify

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    # Force HTTPS
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Content Security Policy
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Enable XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Remove server info
    response.headers.pop('Server', None)
    
    return response





### **7. Add Rate Limiting Section**


##  Rate Limiting

### DO THIS - Implement Rate Limiting


from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379"  # Use Redis for distributed limiting
)

# Apply to routes
@app.route("/api/login")
@limiter.limit("5 per minute")  # Strict limit for auth
def login():
    return {"status": "login"}

@app.route("/api/data")
@limiter.limit("100 per minute")  # Looser limit for data
def get_data():
    return {"data": "sensitive"}

# Dynamic limits based on user role
@app.route("/api/admin")
@limiter.limit(lambda: "100 per day" if current_user.is_admin else "10 per day")
def admin_endpoint():
    return {"status": "admin"}