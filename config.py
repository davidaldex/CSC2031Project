import base64,os,re
from functools import wraps
from hashlib import scrypt

from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from flask import Flask, url_for, flash, redirect, abort, render_template, request

from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink

from flask_qrcode import QRcode
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_talisman import Talisman
from sqlalchemy import MetaData, Enum
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import pyotp, secrets, logging
from argon2 import PasswordHasher
from dotenv import load_dotenv

# Load the .env file
load_dotenv()

# Initialize the Limiter
limiter = Limiter(
    key_func=get_remote_address,  # Identifies clients based on IP address
    default_limits=["500 per day"] # Default limit of 500 requests per day
)

# PasswordHasher instance for hashing passwords securely
ph = PasswordHasher()

# Initialize the Flask application
app = Flask(__name__)
limiter.init_app(app)  # Attach rate limiter to Flask app

# Custom Content Security Policy (CSP) to restrict resources to trusted sources
csp = {
    'default-src': '\'self\'',  # Default to same-origin for resources
    'style-src': [
        '\'self\'',  # Allow inline styles and Bootstrap CSS
        'https://cdn.jsdelivr.net',
        "'unsafe-inline'",  # Allow inline styles for form error messages
    ],
    'script-src': [
        '\'self\'',  # Allow scripts from same origin and CDN resources
        'https://cdn.jsdelivr.net',
        'https://www.google.com/recaptcha/',
        'https://www.gstatic.com/recaptcha/',
    ],
    'frame-src': [
        'https://www.google.com/recaptcha/',
        'https://recaptcha.google.com/recaptcha/',
    ],
    'font-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net',
        'https://fonts.gstatic.com',
    ],
    'img-src': [
        '\'self\'',  # Local images
        'data:',  # Allow base64 inline images
    ],
    'connect-src': [
        '\'self\'',
        'https://www.google.com/recaptcha/',
    ],
}

# Apply the CSP header to the Flask app for security
talisman = Talisman(app, content_security_policy=csp)

# Set up Flask-Login for handling user authentication and session management
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'accounts.login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "danger"

# Define how to load a user based on user ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Function to generate a key for symmetric encryption based on a password and salt
def generate_key(password, salt):
    key = scrypt(
        password=password.encode(),
        salt=salt.encode(),
        n=2048,
        r=8,
        p=1,
        dklen=32
    )
    return base64.urlsafe_b64encode(key)

# Functions to encrypt and decrypt text using Fernet symmetric encryption
def encrypt_text(key, text):
    # Encrypt text using Fernet.
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()
def decrypt_text(key, encrypted_text):
    # Decrypt text using Fernet.
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_text.encode()).decode()

# SECRET KEY FOR FLASK FORMS
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
# Site and Secret Keys for Recaptcha:
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')
# DATABASE CONFIGURATION
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///default.db')  # Fallback DB URI
app.config['SQLALCHEMY_ECHO'] = os.getenv('SQLALCHEMY_ECHO', 'False') == 'True'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'
app.config['FLASK_ADMIN_FLUID_LAYOUT'] = os.getenv('FLASK_ADMIN_FLUID_LAYOUT', 'False') == 'True'

# Metadata for SQLAlchemy, defining naming conventions for database constraints
metadata = MetaData(
    naming_convention={
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
    }
)
# Initialize SQLAlchemy and Flask-Migrate for database management
db = SQLAlchemy(app, metadata=metadata)
migrate = Migrate(app, db)

# Set up logging for security-related events
logger = logging.getLogger('security_logger')
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler('security.log', mode='a')
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Define Web Application Firewall (WAF) rules to protect against common attacks
conditions = {
    "SQL Injection": re.compile(r"(union|select|insert|drop|alter|;|`|')", re.IGNORECASE),
    "XSS": re.compile(r"(<script>|<iframe>|%3Cscript%3E|%3Ciframe%3E)", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./|\.\.|%2e%2e%2f|%2e%2e/|\.\.%2f)", re.IGNORECASE)
}
# Function to implement WAF protection on each request
@app.before_request
def waf_protect():
    for attack_type, attack_pattern in conditions.items():
        if attack_pattern.search(request.path) or attack_pattern.search(request.query_string.decode()):
            # Block the request and return an error page if malicious patterns are detected
            return render_template("errors/error.html", attack_label=attack_type), 403

# Define database tables for the application: Post and User models with relationships
class Post(db.Model):
   __tablename__ = 'posts'
   id = db.Column(db.Integer, primary_key=True)
   user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
   created = db.Column(db.DateTime, nullable=False)
   encrypted_title = db.Column(db.Text, nullable=False)  # Encrypted title
   encrypted_body = db.Column(db.Text, nullable=False)  # Encrypted body
   user = db.relationship("User", back_populates="posts")

   def __init__(self, encrypted_title, encrypted_body, user_id):
       self.created = datetime.now()
       self.encrypted_title = encrypted_title
       self.encrypted_body = encrypted_body
       self.user_id = user_id

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    # User posts
    posts = db.relationship("Post", order_by=Post.id, back_populates="user")
    # New fields for MFA
    mfa_key = db.Column(db.String(32), nullable=False, default=lambda: pyotp.random_base32())
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    # Relationship with logs
    role = db.Column(Enum('end_user', 'db_admin', 'sec_admin', name='user_roles'), nullable=False, default='end_user')
    logs = db.relationship('Log', back_populates='user', uselist=False)
    salt = db.Column(db.String(100), nullable=False)

    def __init__(self, email, firstname, lastname, phone, password, role='end_user'):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = ph.hash(password)

        self.mfa_key = pyotp.random_base32()  # Generate a random MFA key for each user
        self.qr_code_uri = str(pyotp.totp.TOTP(self.mfa_key).provisioning_uri(email, issuer_name="C3010220 Blog"))

        self.role = role
        self.salt = base64.b64encode(secrets.token_bytes(32)).decode()

    def verify_password(self, password):
        try:
            return ph.verify(self.password, password)
        except VerifyMismatchError:
            return False

    def verify_mfa_pin(self, mfa_key, mfa_pin):
        return pyotp.TOTP(mfa_key).verify(mfa_pin)

    def create_log(self):
        """Creates a new log entry when a user is registered."""
        log = Log(user_id=self.id)
        db.session.add(log)
        db.session.commit()

    def update_login_log(self, ip_address):
        """Updates the login log for a user after a successful login."""
        log = self.logs
        if log:
            log.previous_login_date = log.latest_login_date
            log.previous_ip = log.latest_ip
            log.latest_login_date = datetime.utcnow()
            log.latest_ip = ip_address
            db.session.commit()

class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    latest_login_date = db.Column(db.DateTime)
    previous_login_date = db.Column(db.DateTime)
    latest_ip = db.Column(db.String(45))  # Supports both IPv4 and IPv6
    previous_ip = db.Column(db.String(45))

    user = db.relationship('User', back_populates='logs', uselist=False)

    def __init__(self, user_id):
        self.user_id = user_id
        self.registration_date = datetime.utcnow()
        self.latest_login_date = None
        self.previous_login_date = None
        self.latest_ip = None
        self.previous_ip = None

# Admin and model views for the Flask-Admin dashboard
class MainIndexLink(MenuLink):
    def get_url(self):
        return url_for('index')

class PostView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'user_id', 'created', 'encrypted_title', 'encrypted_body', 'user')

    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'db_admin'

    def inaccessible_callback(self, name, **kwargs):
        if current_user.is_authenticated:
            # Log the unauthorized access attempt
            logger.warning(
                f"Unauthorized Role Access Attempt [User Email={current_user.email}, User Role={current_user.role}, "
                f"URL={request.url}, IP={request.remote_addr}]")
            return render_template('errors/forbidden.html'), 403
        flash("Access denied. Only database administrators can access this page.", 'danger')
        return redirect(url_for('accounts.login'))

class UserView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'email', 'password', 'firstname', 'lastname', 'phone', 'mfa_key', 'mfa_enabled')

    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'db_admin'

    def inaccessible_callback(self, name, **kwargs):
        if current_user.is_authenticated:
            # Log the unauthorized access attempt
            logger.warning(
                f"Unauthorized Role Access Attempt [User Email={current_user.email}, User Role={current_user.role}, "
                f"URL={request.url}, IP={request.remote_addr}]")
            return render_template('errors/forbidden.html'), 403
        flash("Access denied. Only database administrators can access this page.", 'danger')
        return redirect(url_for('accounts.login'))

def update(self, title, body):
    self.created = datetime.now()
    self.title = title
    self.body = body
    db.session.commit()

def role_required(*roles):
    """Decorator to restrict access based on user roles."""
    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                # Log the unauthorized access attempt
                logger.warning(
                    f"Unauthorized Role Access Attempt [User Email={current_user.email}, User Role={current_user.role}, "
                    f"URL={request.url}, IP={request.remote_addr}]")

                return render_template('errors/forbidden.html'), 403
            return func(*args, **kwargs)
        return wrapped
    return decorator

admin = Admin(app, name='DB Admin', template_mode='bootstrap4')
admin._menu = admin._menu[1:]
admin.add_link(MainIndexLink(name='Home Page'))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))

qrcode = QRcode(app=app)

# IMPORT BLUEPRINTS
from accounts.views import accounts_bp
from posts.views import posts_bp
from security.views import security_bp

# REGISTER BLUEPRINTS
app.register_blueprint(accounts_bp)
app.register_blueprint(posts_bp)
app.register_blueprint(security_bp)