from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os
from datetime import datetime

app = Flask(__name__, template_folder='app')
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default_secret_key")

# Configure PostgreSQL database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure connection pool settings
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

from models import User, Message, ChatRoom

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

with app.app_context():
    # Create tables if they don't exist
    db.create_all()
    
# Register Google Auth Blueprint
from google_auth import google_auth
app.register_blueprint(google_auth)