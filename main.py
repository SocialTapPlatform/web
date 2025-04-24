from flask import render_template, request, session, jsonify, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, ValidationError, EqualTo
from flask import Flask, request, abort, send_file
from flask import redirect
from app import app, db
from models import User, Message, ChatRoom, cipher_suite
import uuid
from datetime import datetime, timedelta
import logging
import os
import re
import time
from flask_cors import CORS

logging.basicConfig(level=logging.DEBUG)

CORS(app)

#These WP bots thinking I'm using WP are getting pretty annoying
@app.before_request
def block_bad_paths():
    if request.path.startswith('/wp-admin/'):
        print(f"[INFO] Bot attempt blocked from IP: {request.remote_addr}, User-Agent: {request.user_agent.string}")
        time.sleep(5)
        return '', 204



@app.errorhandler(500)
def handle_500(e):
    if request.path.startswith("/api/"):
        # sus
        return jsonify({"error": "Internal server error"}), 500
    else:
       
        return redirect("https://http.cat/500")
#Letting cats handle all of the error messages
@app.errorhandler(Exception)
def handle_exception(e):
    code = getattr(e, 'code', 500)
    return redirect(f"https://http.cat/{code}")




# Load blacklist words
BLACKLIST_WORDS = set()
try:
    if os.path.exists('blacklist.txt'):
        with open('blacklist.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    BLACKLIST_WORDS.add(line.lower())
        logging.info(f"Loaded {len(BLACKLIST_WORDS)} words to blacklist")
except Exception as e:
    logging.error(f"Failed to load blacklist: {str(e)}")

def contains_blacklisted_words(text):
    """Check if text contains any blacklisted words"""
    if not text:
        return False, []
    
    text_lower = text.lower()
    found_words = []
    
    # Check for exact matches (with word boundaries)
    for word in BLACKLIST_WORDS:
        pattern = r'\b' + re.escape(word) + r'\b'
        if re.search(pattern, text_lower):
            found_words.append(word)
    
    return bool(found_words), found_words

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken.')

    def validate_email(self, email):
        try:
            # Check if any user already has this email
            user = User.query.filter_by(_email=cipher_suite.encrypt(email.data.encode()).decode()).first()
            if user:
                raise ValidationError('Email already registered.')
        except Exception as e:
            logging.error(f"Error validating email: {str(e)}")
            raise ValidationError('Error validating email. Please try again.')
            
class DeleteAccountForm(FlaskForm):
    confirm_delete = BooleanField('I understand this action cannot be undone', validators=[DataRequired()])
    submit = SubmitField('Delete Account')

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Update last seen timestamp
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    
    # Get all chat rooms the user is part of
    chat_rooms = current_user.chats.all()
    
    return render_template('index.html', 
                          username=current_user.username, 
                          chat_rooms=chat_rooms,
                          active_chat_id=None,
                          current_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        try:
            # Get all users and compare decrypted emails
            users = User.query.all()
            user = next((u for u in users if u.email == form.email.data), None)

            if user and user.check_password(form.password.data):
                login_user(user)
                return redirect(url_for('index'))
                logging.info(f"User {user.username} logged in successfully")
                return redirect(url_for('index'))
            flash('Invalid email or password')
            logging.warning(f"Failed login attempt for email: {form.email.data}")
        except Exception as e:
            logging.error(f"Login error: {str(e)}", exc_info=True)
            flash('An error occurred during login. Please try again.')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data

        # Max length check
        if len(username) > 15:
            logging.warning(f"Blocked registration attempt (too long): {username}")
            return redirect('https://http.cat/images/413.jpg')

        # Invalid character check (only a-z, A-Z, 0-9, _)
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            logging.warning(f"Blocked registration attempt (invalid characters): {username}")
            return redirect('https://http.cat/400')

        # Blacklist check (case insensitive)
        lower_username = username.lower()
        for word in BLACKLIST_WORDS:
            if word in lower_username:
                logging.warning(f"Blocked registration attempt (blacklisted word): {username}")
                return redirect('https://http.cat/403')

        try:
            user = User(username=username)
            user.email = form.email.data  
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            logging.info(f"User registered successfully: {user.username}")
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            logging.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.')

    return render_template('register.html', form=form)

#regend
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat/<int:chat_id>')
@login_required
def view_chat(chat_id):
    chat_room = ChatRoom.query.get_or_404(chat_id)
    
    # Check if user is a participant in this chat
    if current_user not in chat_room.participants:
        flash('You do not have access to this chat room.')
        return redirect(url_for('index'))
    
    # Update last seen timestamp
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    
    # Get all chat rooms the user is part of
    chat_rooms = current_user.chats.all()
    
    return render_template('index.html', 
                          username=current_user.username, 
                          chat_rooms=chat_rooms,
                          active_chat_id=chat_id,
                          current_user=current_user)

@app.route('/messages')
@login_required
def get_messages():
    chat_id = request.args.get('chat_id', type=int)
    
    if chat_id:
        # Get messages for a specific chat room
        chat_room = ChatRoom.query.get_or_404(chat_id)
        if current_user not in chat_room.participants:
            return jsonify({'error': 'Access denied'}), 403
            
        messages = Message.query.filter_by(chat_room_id=chat_id).order_by(Message.timestamp.asc()).all()
    else:
        # Get messages for the global chat (messages without a chat_room_id)
        messages = Message.query.filter_by(chat_room_id=None).order_by(Message.timestamp.asc()).all()
    
    return jsonify([{
        'id': msg.id,
        'content': msg.content,
        'username': msg.author.username,
        'timestamp': msg.timestamp.strftime('%H:%M')
    } for msg in messages])

@app.route('/send', methods=['POST'])
@login_required
def send_message():
    content = request.form.get('message', '').strip()
    chat_id = request.form.get('chat_id', type=int)
    
    if not content:
        return jsonify({'error': 'Message cannot be empty'}), 400
        
    # Check cooldown
    now = datetime.utcnow()
    last_message = Message.query.filter_by(user_id=current_user.id).order_by(Message.timestamp.desc()).first()
    if last_message and (now - last_message.timestamp).total_seconds() < 2:
        return jsonify({'error': 'Please wait 2 seconds between messages'}), 429
    
    # Check for blacklisted words
    has_blacklisted, found_words = contains_blacklisted_words(content)
    if has_blacklisted:
        logging.warning(f"User {current_user.username} attempted to send message with blacklisted words: {', '.join(found_words)}")
        return jsonify({
            'error': 'Your message contains inappropriate language',
            'blacklisted_words': found_words
        }), 400
    
    # Update user's last seen timestamp
    current_user.last_seen = datetime.utcnow()
    
    if chat_id:
        # Check if user has access to this chat room
        chat_room = ChatRoom.query.get_or_404(chat_id)
        if current_user not in chat_room.participants:
            return jsonify({'error': 'Access denied'}), 403
            
        message = Message(content=content, author=current_user, chat_room=chat_room)
    else:
        # Send to global chat
        message = Message(content=content, author=current_user)
    
    db.session.add(message)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': {
            'id': message.id,
            'content': message.content,
            'username': current_user.username,
            'timestamp': message.timestamp.strftime('%H:%M')
        }
    })

@app.route('/api/users')
@login_required
def get_users():
    # Update user's last seen timestamp
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    
    # Get all users except current user
    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
    online_users = User.query.filter(
        User.id != current_user.id,
        User.last_seen >= five_minutes_ago
    ).all()
    
    return jsonify([{
        'id': user.id,
        'username': user.username
    } for user in online_users])

@app.route('/api/chats')
@login_required
def get_chats():
    # Update user's last seen timestamp
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    
    # Get all chat rooms the user is part of
    chat_rooms = current_user.chats.all()
    
    return jsonify([chat.to_dict() for chat in chat_rooms])

@app.route('/api/chats/create', methods=['POST'])
@login_required
def create_chat():
    user_id = request.form.get('user_id', type=int)
    
    if not user_id:
        return jsonify({'error': 'User ID is required'}), 400
        
    # Check if user exists
    other_user = User.query.get_or_404(user_id)
    
    # Check if a chat already exists between these users
    existing_chats = current_user.chats.all()
    for chat in existing_chats:
        if other_user in chat.participants and len(list(chat.participants)) == 2:
            return jsonify({
                'success': True,
                'chat': chat.to_dict()
            })
    
    # Create a new chat room
    chat_name = f"Chat with {other_user.username}"
    chat_room = ChatRoom(name=chat_name, is_private=True)
    
    # Add both users as participants
    chat_room.participants.append(current_user)
    chat_room.participants.append(other_user)
    
    db.session.add(chat_room)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'chat': chat_room.to_dict()
    })

@app.route('/api/user/offline', methods=['POST'])
@login_required
def set_user_offline():
    # Set the user's last_seen time to a time in the past (more than 5 minutes ago)
    current_user.last_seen = datetime.utcnow() - timedelta(minutes=10)
    db.session.commit()
    
    return '', 204  # Return empty response with HTTP 204 (No Content)

@app.route('/profile', methods=['GET'])
def profile():
    # Update last seen timestamp
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    
    delete_form = DeleteAccountForm()
    
    return render_template('profile.html', user=current_user, delete_form=delete_form)
    
@app.route('/confirm-google-delete')
@login_required
def confirm_google_delete():
    if not current_user.is_google_user:
        flash('This action is only available for Google-authenticated users.', 'danger')
        return redirect(url_for('profile'))
        
    # Create a simple confirmation form
    class ConfirmGoogleDeleteForm(FlaskForm):
        confirm_delete = BooleanField('I understand this action cannot be undone', validators=[DataRequired()])
        submit = SubmitField('Delete My Account')
        
    form = ConfirmGoogleDeleteForm()
    
    return render_template('confirm_google_delete.html', form=form, user=current_user)
    
@app.route('/execute-google-delete', methods=['POST'])
@login_required
def execute_google_delete():
    if not current_user.is_google_user:
        flash('This action is only available for Google-authenticated users.', 'danger')
        return redirect(url_for('profile'))
        
    # Create a simple confirmation form
    class ConfirmGoogleDeleteForm(FlaskForm):
        confirm_delete = BooleanField('I understand this action cannot be undone', validators=[DataRequired()])
        submit = SubmitField('Delete My Account')
        
    form = ConfirmGoogleDeleteForm()
    
    if form.validate_on_submit():
        user_id = current_user.id
        user_username = current_user.username
        
        try:
            # Remove user from all chat participants
            for chat in current_user.chats:
                # If this is a private chat and only 2 participants, delete the entire chat
                if chat.is_private and chat.participants.count() <= 2:
                    # Delete all messages in the chat first
                    Message.query.filter_by(chat_room_id=chat.id).delete()
                    db.session.flush()  # Flush to ensure messages are deleted before the chat
                    db.session.delete(chat)
                else:
                    # For group chats or public chats, just remove this user
                    chat.participants.remove(current_user)
            
            # Delete all messages by this user
            Message.query.filter_by(user_id=user_id).delete()
            
            # Log the user out
            logout_user()
            
            # Delete the user
            User.query.filter_by(id=user_id).delete()
            db.session.commit()
            
            flash('Your account has been permanently deleted.')
            logging.info(f"User {user_username} (ID: {user_id}) deleted their account via Google authentication")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error deleting Google user account: {str(e)}", exc_info=True)
            flash('An error occurred while deleting your account. Please try again.')
            return redirect(url_for('profile'))
        
    # If form validation failed
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{getattr(form, field).label.text}: {error}", 'danger')
    
    return redirect(url_for('profile'))

@app.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    form = DeleteAccountForm()
    
    if form.validate_on_submit():
        user_id = current_user.id
        user_username = current_user.username
        
        try:
            # Remove user from all chat participants
            for chat in current_user.chats:
                # If this is a private chat and only 2 participants, delete the entire chat
                if chat.is_private and chat.participants.count() <= 2:
                    # Delete all messages in the chat first
                    Message.query.filter_by(chat_room_id=chat.id).delete()
                    db.session.flush()  # Flush to ensure messages are deleted before the chat
                    db.session.delete(chat)
                else:
                    # For group chats or public chats, just remove this user
                    chat.participants.remove(current_user)
                
                # Delete all messages by this user
            Message.query.filter_by(user_id=user_id).delete()
            
            # Log the user out
            logout_user()
            
            # Delete the user
            User.query.filter_by(id=user_id).delete()
            db.session.commit()
            
            flash('Your account has been permanently deleted.')
            logging.info(f"User {user_username} (ID: {user_id}) deleted their account")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error deleting user account: {str(e)}", exc_info=True)
            flash('An error occurred while deleting your account. Please try again.')
            return redirect(url_for('profile'))
    else:
        flash('Incorrect password. Account deletion canceled.')
        return redirect(url_for('profile'))
            
    flash('Please confirm your decision to delete your account.')
    return redirect(url_for('profile'))

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/google924ae39ef02b1cc5.html')
def google924ae39ef02b1cc5():
    return render_template('/google924ae39ef02b1cc5.html')
    
@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms_of_service.html')

@app.route('/download')
def download():
    return render_template('/download.html')

@app.route('/download/<platform>')
def download_platform(platform):
    if platform == 'windows':
        return redirect(url_for('static', filename='releases/SocialTap-Setup.exe'))
    elif platform == 'macos':
        return redirect(url_for('static', filename='releases/SocialTap.dmg'))
    else:
        return redirect(url_for('download'))

# Admin routes
@app.route('/admin/ban-user/<int:user_id>', methods=['POST'])
@login_required
def ban_user(user_id):
    if not current_user.is_admin():
        flash('Access denied. Administrative privileges required.', 'danger')
        return redirect(url_for('index'))
    
    user_to_ban = User.query.get_or_404(user_id)
    
    # Don't allow banning yourself or other admins
    if user_to_ban.id == current_user.id or user_to_ban.is_admin():
        flash('Cannot ban this user.', 'danger')
        return redirect(url_for('index'))
    
    user_to_ban.is_banned = True
    db.session.commit()
    
    flash(f'User {user_to_ban.username} has been banned.', 'success')
    logging.info(f"Admin {current_user.username} banned user {user_to_ban.username} (ID: {user_to_ban.id})")
    return redirect(url_for('index'))

@app.route('/admin/unban-user/<int:user_id>', methods=['POST'])
@login_required
def unban_user(user_id):
    if not current_user.is_admin():
        flash('Access denied. Administrative privileges required.', 'danger')
        return redirect(url_for('index'))
    
    user_to_unban = User.query.get_or_404(user_id)
    
    user_to_unban.is_banned = False
    db.session.commit()
    
    flash(f'User {user_to_unban.username} has been unbanned.', 'success')
    logging.info(f"Admin {current_user.username} unbanned user {user_to_unban.username} (ID: {user_to_unban.id})")
    return redirect(url_for('index'))

@app.route('/admin/delete-message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    if not current_user.is_admin():
        flash('Access denied. Administrative privileges required.', 'danger')
        return redirect(url_for('index'))
    
    message = Message.query.get_or_404(message_id)
    
    # Store info for logging
    msg_content = message.content[:50] + "..." if len(message.content) > 50 else message.content
    msg_author = message.author.username
    
    db.session.delete(message)
    db.session.commit()
    
    logging.info(f"Admin {current_user.username} deleted message from {msg_author}: '{msg_content}'")
    
    # If this was an AJAX request, return JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'message': 'Message deleted successfully'})
    
    # Otherwise, redirect back
    flash('Message deleted successfully.', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin():
        flash('Access denied. Administrative privileges required.', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin_users.html', users=users, current_user=current_user)

@app.route('/admin/delete-account/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_account(user_id):
    if not current_user.is_admin():
        flash('Access denied. Administrative privileges required.', 'danger')
        return redirect(url_for('index'))
    
    # Prevent admins from deleting themselves through this route
    if user_id == current_user.id:
        flash('You cannot delete your own account through the admin panel. Use the profile page instead.', 'danger')
        return redirect(url_for('admin_users'))
    
    user_to_delete = User.query.get_or_404(user_id)
    user_username = user_to_delete.username
    
    try:
        # Remove user from all chat participants
        for chat in user_to_delete.chats:
            # If this is a private chat and only 2 participants, delete the entire chat
            if chat.is_private and chat.participants.count() <= 2:
                # Delete all messages in the chat first
                Message.query.filter_by(chat_room_id=chat.id).delete()
                db.session.flush()  # Flush to ensure messages are deleted before the chat
                db.session.delete(chat)
            else:
                # For group chats or public chats, just remove this user
                chat.participants.remove(user_to_delete)
        
        # Delete all messages by this user
        Message.query.filter_by(user_id=user_id).delete()
        
        # Store the username for the log message
        admin_username = current_user.username
        
        # Delete the user
        User.query.filter_by(id=user_id).delete()
        db.session.commit()
        
        # Log the deletion
        logging.info(f"Admin {admin_username} deleted user account: {user_username} (ID: {user_id})")
        
        flash(f'User account "{user_username}" has been permanently deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting user account: {str(e)}")
        flash(f'Error deleting account: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        abort(403)

    user = User.query.get_or_404(user_id)

    if user.is_admin() or user.id == current_user.id:
        flash('Cannot delete this user.', 'danger')
        return redirect(url_for('admin_users'))

    # Delete user's messages first
    Message.query.filter_by(user_id=user.id).delete()

    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} and their messages have been deleted.', 'success')
    return redirect(url_for('admin_panel'))
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)



#delete this below if something goes wrong
@app.route('/api/chats/delete/<int:chat_id>', methods=['DELETE'])
def delete_chat(chat_id):
    # Prevent deletion of chat ID 0
    if chat_id == 0:
        return jsonify({"error": "Chat ID 0 cannot be deleted."}), 400

    # Get the user ID from the request (you can modify this part based on your authentication method)
    user_id = request.json.get('user_id')  # Assuming you're sending the user ID in the request body
    
    if not user_id:
        return jsonify({"error": "User ID is required."}), 400

    # Connect to the database
    conn = get_db_connection()

    # Check if the user has sent the message (chat) before
    query = "SELECT * FROM messages WHERE chat_id = ? AND user_id = ?"
    message = conn.execute(query, (chat_id, user_id)).fetchone()

    # If the user has not sent the message, deny the deletion
    if not message:
        conn.close()
        return jsonify({"error": "You have not sent this message and cannot delete it."}), 403

    # If the user sent the message, proceed with the deletion
    delete_query = "DELETE FROM messages WHERE chat_id = ? AND user_id = ?"
    conn.execute(delete_query, (chat_id, user_id))
    conn.commit()
    conn.close()

    return jsonify({"success": "Chat deleted successfully."}), 200
