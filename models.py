
from datetime import datetime
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os

# Initialize encryption key from environment variable
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    # Generate a new key if none exists - but this should be saved to env vars
    ENCRYPTION_KEY = Fernet.generate_key()
    print("WARNING: No encryption key found in environment variables. Generated temporary key.")
    print("Please add this key to your environment variables:")
    print(ENCRYPTION_KEY.decode())
cipher_suite = Fernet(ENCRYPTION_KEY if isinstance(ENCRYPTION_KEY, bytes) else ENCRYPTION_KEY.encode())

# Association table for many-to-many relationship between ChatRoom and User
chat_participants = db.Table('chat_participants',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('chat_room_id', db.Integer, db.ForeignKey('chat_room.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    _email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_google_user = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    messages = db.relationship('Message', backref='author', lazy='dynamic')
    
    # Relationship with ChatRoom
    chats = db.relationship('ChatRoom', secondary=chat_participants, 
                           backref=db.backref('participants', lazy='dynamic'), 
                           lazy='dynamic')

    @property
    def email(self):
        try:
            if self._email:
                return cipher_suite.decrypt(self._email.encode()).decode()
        except:
            return None
        return None

    @email.setter
    def email(self, value):
        if value:
            self._email = cipher_suite.encrypt(value.encode()).decode()

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def is_online(self):
        now = datetime.utcnow()
        delta = now - self.last_seen if self.last_seen else None
        # Consider a user online if they've been active in the last 5 minutes
        return delta and delta.total_seconds() < 300
        
    def is_admin(self):
        # Check if the user's email is in admins.txt file
        try:
            with open('admins.txt', 'r') as f:
                admin_emails = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                return self.email in admin_emails
        except Exception as e:
            print(f"Error checking admin status: {str(e)}")
            return False

class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))
    is_private = db.Column(db.Boolean, default=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    messages = db.relationship('Message', backref='chat_room', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'is_private': self.is_private,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M'),
            'participants': [{'id': user.id, 'username': user.username} for user in self.participants]
        }

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    chat_room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=True)
