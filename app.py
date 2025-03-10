from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from pymongo import MongoClient
from bson import ObjectId
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from datetime import datetime, timedelta
import pandas as pd
import io
import re
import requests
from config import Config
from utils.storage import storage
import qrcode

app = Flask(__name__)
app.config.from_object(Config)

# Ensure session cookie settings are secure
app.config['SESSION_COOKIE_SECURE'] = True  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

# MongoDB configuration
client = MongoClient(Config.MONGODB_URI)
db = client[Config.MONGODB_DB_NAME]
documents = db.documents
users = db.users
telegram_subscriptions = db.telegram_subscriptions

# Initialize first admin if no users exist
with app.app_context():
    if users.count_documents({}) == 0:
        first_admin = {
            'username': 'admin',
            'password': generate_password_hash('admin'),  # Change this password in production
            'first_name': 'Admin',
            'last_name': 'User',
            'email': 'admin@example.com',
            'phone': '+1234567890',
            'role': 'admin',
            'is_first_admin': True,
            'created_at': datetime.utcnow(),
            'status': 'active'
        }
        users.insert_one(first_admin)

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first', 'warning')
            return redirect(url_for('login'))
        
        # Check if user is approved (active)
        user = users.find_one({'_id': ObjectId(session['user_id'])})
        if not user or user.get('status') != 'active':
            # If user exists but is not active, redirect to pending approval
            if user:
                session.pop('user_id', None)
                session.pop('name', None)
                session.pop('role', None)
                session['pending_user_id'] = str(user['_id'])
                session['pending_username'] = user['username']
                flash('Your account is pending approval by an administrator.', 'warning')
                return redirect(url_for('pending_approval'))
            # If user doesn't exist (deleted), log them out
            else:
                session.clear()
                flash('Your account no longer exists. Please contact an administrator.', 'danger')
                return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first', 'warning')
            return redirect(url_for('login'))
        
        user = users.find_one({'_id': ObjectId(session['user_id'])})
        if not user or user.get('status') != 'active':
            # Handle inactive user
            session.pop('user_id', None)
            session.pop('name', None)
            session.pop('role', None)
            if user:
                session['pending_user_id'] = str(user['_id'])
                session['pending_username'] = user['username']
                flash('Your account is pending approval by an administrator.', 'warning')
                return redirect(url_for('pending_approval'))
            else:
                session.clear()
                flash('Your account no longer exists. Please contact an administrator.', 'danger')
                return redirect(url_for('login'))
        
        if user['role'] != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def supervisor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first', 'warning')
            return redirect(url_for('login'))
        
        user = users.find_one({'_id': ObjectId(session['user_id'])})
        if not user or user.get('status') != 'active':
            # Handle inactive user
            session.pop('user_id', None)
            session.pop('name', None)
            session.pop('role', None)
            if user:
                session['pending_user_id'] = str(user['_id'])
                session['pending_username'] = user['username']
                flash('Your account is pending approval by an administrator.', 'warning')
                return redirect(url_for('pending_approval'))
            else:
                session.clear()
                flash('Your account no longer exists. Please contact an administrator.', 'danger')
                return redirect(url_for('login'))
        
        if user['role'] not in ['admin', 'supervisor']:
            flash('Supervisor access required', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Add document owner check decorator
def document_owner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first', 'warning')
            return redirect(url_for('login'))
        
        # Check if user is approved (active)
        user = users.find_one({'_id': ObjectId(session['user_id'])})
        if not user or user.get('status') != 'active':
            # Handle inactive user
            session.pop('user_id', None)
            session.pop('name', None)
            session.pop('role', None)
            if user:
                session['pending_user_id'] = str(user['_id'])
                session['pending_username'] = user['username']
                flash('Your account is pending approval by an administrator.', 'warning')
                return redirect(url_for('pending_approval'))
            else:
                session.clear()
                flash('Your account no longer exists. Please contact an administrator.', 'danger')
                return redirect(url_for('login'))
        
        document_id = kwargs.get('document_id')
        if not document_id:
            flash('Document not found', 'danger')
            return redirect(url_for('index'))
        
        try:
            document = documents.find_one({'_id': ObjectId(document_id)})
            if not document:
                flash('Document not found', 'danger')
                return redirect(url_for('index'))
            
            if user['role'] not in ['admin', 'supervisor'] and str(document.get('user_id', '')) != session['user_id']:
                flash('You do not have permission to access this document', 'danger')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        except Exception as e:
            flash(f'Error accessing document: {str(e)}', 'danger')
            return redirect(url_for('index'))
    return decorated_function

# Add email validation function
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Clear any existing pending user session
    if 'pending_user_id' in session:
        session.pop('pending_user_id', None)
        session.pop('pending_username', None)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = users.find_one({'username': username})
        
        if user and check_password_hash(user['password'], password):
            # Check if user is approved (active)
            if user.get('status') != 'active':
                # Store pending user info in session
                session['pending_user_id'] = str(user['_id'])
                session['pending_username'] = user['username']
                flash('Your account is pending approval by an administrator.', 'warning')
                return redirect(url_for('pending_approval'))
            
            # User is active, proceed with login
            session['user_id'] = str(user['_id'])
            session['name'] = f"{user['first_name']} {user['last_name']}"
            session['role'] = user.get('role', 'user')
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/pending-approval')
def pending_approval():
    # Check if user is in pending state
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))
    
    # Ensure any regular user session is cleared
    if 'user_id' in session:
        session.pop('user_id', None)
        session.pop('name', None)
        session.pop('role', None)
    
    # Check if the pending user still exists and is still pending
    try:
        user = users.find_one({'_id': ObjectId(session['pending_user_id'])})
        if not user:
            # User no longer exists
            session.clear()
            flash('Your account no longer exists. Please contact an administrator.', 'danger')
            return redirect(url_for('login'))
        
        # Double check that the user is actually pending
        if user.get('status') != 'pending':
            if user.get('status') == 'active':
                # User has been approved, redirect to login
                session.clear()
                flash('Your account has been approved! Please login to continue.', 'success')
                return redirect(url_for('login'))
            else:
                # User has some other status
                session.clear()
                flash('Your account status has changed. Please contact an administrator.', 'warning')
                return redirect(url_for('login'))
    except Exception as e:
        # Handle any errors
        session.clear()
        flash(f'An error occurred: {str(e)}', 'danger')
        return redirect(url_for('login'))
    
    return render_template('pending_approval.html', username=session.get('pending_username'))

# User management routes
@app.route('/users')
@admin_required
def list_users():
    # Get all users and sort by status (pending first) and then by creation date
    user_list = list(users.find().sort([("status", -1), ("created_at", -1)]))
    
    # Count pending users for notification
    pending_count = users.count_documents({"status": "pending"})
    
    current_user = users.find_one({'_id': ObjectId(session['user_id'])})
    return render_template('users.html', 
                          users=user_list, 
                          current_user=current_user,
                          pending_count=pending_count)

@app.route('/users/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if users.find_one({'username': username}):
            flash('Username already exists', 'danger')
            return redirect(url_for('add_user'))
        
        new_user = {
            'username': username,
            'password': generate_password_hash(password),
            'role': role,
            'is_first_admin': False,
            'created_at': datetime.utcnow()
        }
        
        users.insert_one(new_user)
        flash('User added successfully', 'success')
        return redirect(url_for('list_users'))
    
    return render_template('add_user.html')

@app.route('/users/edit/<user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = users.find_one({'_id': ObjectId(user_id)})
    current_user = users.find_one({'_id': ObjectId(session['user_id'])})
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('list_users'))
    
    # Only first admin can modify other admins
    if user['role'] == 'admin' and not current_user.get('is_first_admin', False):
        flash('Only the first admin can modify other admins', 'danger')
        return redirect(url_for('list_users'))
    
    if request.method == 'POST':
        new_role = request.form.get('role')
        new_password = request.form.get('password')
        
        update_data = {'role': new_role}
        if new_password:
            update_data['password'] = generate_password_hash(new_password)
        
        users.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})
        flash('User updated successfully', 'success')
        return redirect(url_for('list_users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/users/delete/<user_id>')
@admin_required
def delete_user(user_id):
    user = users.find_one({'_id': ObjectId(user_id)})
    current_user = users.find_one({'_id': ObjectId(session['user_id'])})
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('list_users'))
    
    # Prevent deleting yourself
    if str(user['_id']) == session['user_id']:
        flash('Cannot delete your own account', 'danger')
        return redirect(url_for('list_users'))
    
    # Only first admin can delete other admins
    if user['role'] == 'admin' and not current_user.get('is_first_admin', False):
        flash('Only the first admin can delete other admins', 'danger')
        return redirect(url_for('list_users'))
    
    users.delete_one({'_id': ObjectId(user_id)})
    flash('User deleted successfully', 'success')
    return redirect(url_for('list_users'))

@app.route('/users/approve/<user_id>')
@admin_required
def approve_user(user_id):
    user = users.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('list_users'))
    
    # Update user status to active
    users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'status': 'active'}}
    )
    
    # Add first and last name if they don't exist
    update_data = {}
    if 'first_name' not in user or not user['first_name']:
        update_data['first_name'] = user['username']
    if 'last_name' not in user or not user['last_name']:
        update_data['last_name'] = ''
    
    if update_data:
        users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_data}
        )
    
    flash(f'User {user["username"]} approved successfully', 'success')
    return redirect(url_for('list_users'))

# Protect existing routes with authentication
@app.route('/')
@login_required
def index():
    # Get user role
    user = users.find_one({'_id': ObjectId(session['user_id'])})
    is_admin_or_supervisor = user['role'] in ['admin', 'supervisor']
    
    # Base query for documents
    doc_query = {}
    if not is_admin_or_supervisor:
        # Regular users can only see their own documents
        doc_query['user_id'] = ObjectId(session['user_id'])
    
    # Get document statistics
    if is_admin_or_supervisor:
        # Admins and supervisors see all document stats
        total_documents = documents.count_documents({})
        pending_documents = documents.count_documents({'status': 'pending'})
        returned_documents = documents.count_documents({'status': 'returned'})
        paired_documents = documents.count_documents({'paired_with': {'$ne': None}})
    else:
        # Regular users only see stats for their documents
        total_documents = documents.count_documents(doc_query)
        pending_documents = documents.count_documents({**doc_query, 'status': 'pending'})
        returned_documents = documents.count_documents({**doc_query, 'status': 'returned'})
        paired_documents = documents.count_documents({**doc_query, 'paired_with': {'$ne': None}})
    
    # Get recent documents (last 5)
    recent_documents = list(documents.find(doc_query).sort('upload_date', -1).limit(5))
    
    # Get user statistics (only for admins and supervisors)
    user_stats = {}
    if is_admin_or_supervisor:
        total_users = users.count_documents({})
        active_users = users.count_documents({'status': 'active'})
        pending_users = users.count_documents({'status': 'pending'})
        
        user_stats = {
            'total_users': total_users,
            'active_users': active_users,
            'pending_users': pending_users
        }
    
    # Add uploader information to recent documents
    for doc in recent_documents:
        try:
            uploader = users.find_one({'_id': doc['user_id']})
            doc['uploader_name'] = uploader['username'] if uploader else "Unknown"
        except:
            doc['uploader_name'] = "Unknown"
    
    return render_template('index.html',
                         stats={
                             'total_documents': total_documents,
                             'pending_documents': pending_documents,
                             'returned_documents': returned_documents,
                             'paired_documents': paired_documents,
                             **user_stats
                         },
                         recent_documents=recent_documents,
                         is_admin_or_supervisor=is_admin_or_supervisor)

def send_telegram_notification(message, notification_type='new_doc'):
    """Send notification to subscribed users based on their settings"""
    subscriptions = telegram_subscriptions.find({'active': True})
    
    for sub in subscriptions:
        try:
            # Get user settings
            user = users.find_one({'_id': sub.get('user_id')})
            if user:
                settings = user.get('telegram_settings', {})
                
                # Check if user wants this type of notification
                setting_key = f'notify_{notification_type}'
                if not settings.get(setting_key, True):
                    continue
            
            url = f"{Config.TELEGRAM_API_URL}/sendMessage"
            data = {
                'chat_id': sub['chat_id'],
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, json=data)
            
            # Log any errors
            if not response.ok:
                print(f"Error sending telegram notification: {response.text}")
                
        except Exception as e:
            print(f"Error sending telegram notification: {e}")

@app.route('/telegram/webhook', methods=['POST'])
def telegram_webhook():
    data = request.get_json()
    
    if 'message' not in data:
        return 'OK'
    
    message = data['message']
    chat_id = message['chat']['id']
    text = message.get('text', '')
    
    if text == '/start':
        # Check if already subscribed
        existing = telegram_subscriptions.find_one({'chat_id': chat_id})
        if existing:
            telegram_subscriptions.update_one(
                {'chat_id': chat_id},
                {'$set': {'active': True}}
            )
            welcome_back = (
                "Welcome back to SHV Document Management System!\n\n"
                "You are now resubscribed to document notifications. "
                "You will receive updates about:\n"
                "- New document uploads\n"
                "- Document updates\n"
                "- Document pairing\n\n"
                "Use /stop to unsubscribe from notifications."
            )
            response = welcome_back
        else:
            # Create new subscription
            telegram_subscriptions.insert_one({
                'chat_id': chat_id,
                'username': message['from'].get('username'),
                'first_name': message['from'].get('first_name'),
                'last_name': message['from'].get('last_name'),
                'active': True,
                'subscribed_at': datetime.utcnow()
            })
            welcome_new = (
                "Welcome to SHV Document Management System!\n\n"
                "You are now subscribed to receive notifications about:\n"
                "- New document uploads\n"
                "- Document updates\n"
                "- Document pairing\n\n"
                "Use /stop to unsubscribe from notifications at any time."
            )
            response = welcome_new
        
        requests.post(
            f"{Config.TELEGRAM_API_URL}/sendMessage",
            json={'chat_id': chat_id, 'text': response, 'parse_mode': 'HTML'}
        )
    
    elif text == '/stop':
        telegram_subscriptions.update_one(
            {'chat_id': chat_id},
            {'$set': {'active': False}}
        )
        response = (
            "Notifications paused.\n\n"
            "You will no longer receive document notifications.\n"
            "Use /start to resubscribe at any time."
        )
        requests.post(
            f"{Config.TELEGRAM_API_URL}/sendMessage",
            json={'chat_id': chat_id, 'text': response}
        )
    
    return 'OK'

# Add a function to pair existing documents with the same BL number
def pair_existing_documents():
    """Pair all existing documents with the same BL number"""
    print("Checking for documents to pair...")
    # Get all unpaired documents
    unpaired_docs = list(documents.find({'paired_with': None}))
    
    # Group by BL number
    bl_groups = {}
    for doc in unpaired_docs:
        bl_number = doc['bl_number']
        if bl_number not in bl_groups:
            bl_groups[bl_number] = []
        bl_groups[bl_number].append(doc)
    
    # Pair documents with the same BL number
    paired_count = 0
    for bl_number, docs in bl_groups.items():
        if len(docs) > 1:
            # Sort by upload date to ensure consistent pairing
            docs.sort(key=lambda x: x['upload_date'])
            
            # Pair documents in order (oldest with second oldest, etc.)
            for i in range(0, len(docs) - 1, 2):
                if i + 1 < len(docs):  # Make sure we have a pair
                    doc1 = docs[i]
                    doc2 = docs[i + 1]
                    
                    # Update both documents with paired information
                    documents.update_one(
                        {'_id': doc1['_id']},
                        {'$set': {
                            'paired_with': doc2['_id'],
                            'status': 'returned' if doc2['status'] == 'returned' else doc1['status']
                        }}
                    )
                    documents.update_one(
                        {'_id': doc2['_id']},
                        {'$set': {'paired_with': doc1['_id']}}
                    )
                    
                    paired_count += 1
    
    print(f"Paired {paired_count} document pairs automatically.")
    return paired_count

# Run the pairing function at startup
with app.app_context():
    # Initialize first admin if no users exist
    if users.count_documents({}) == 0:
        first_admin = {
            'username': 'admin',
            'password': generate_password_hash('admin'),  # Change this password in production
            'first_name': 'Admin',
            'last_name': 'User',
            'email': 'admin@example.com',
            'phone': '+1234567890',
            'role': 'admin',
            'is_first_admin': True,
            'created_at': datetime.utcnow(),
            'status': 'active'
        }
        users.insert_one(first_admin)
    
    # Pair existing documents
    pair_existing_documents()

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_document():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(url_for('upload_document'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(url_for('upload_document'))
        
        if file:
            # Get form data
            bl_number = request.form.get('bl_number')
            consignee = request.form.get('consignee')
            declarant_company = request.form.get('declarant_company', '')
            document_holder = request.form.get('document_holder')
            document_holder_phone = request.form.get('document_holder_phone')
            status = request.form.get('status')
            
            # Get SAD details if status is returned
            sad_number = None
            sad_date = None
            sad_type = None
            if status == 'returned':
                sad_number = request.form.get('sad_number')
                sad_date_str = request.form.get('sad_date')
                sad_type = request.form.get('sad_type')
                
                if sad_date_str:
                    try:
                        sad_date = datetime.strptime(sad_date_str, '%Y-%m-%d')
                    except ValueError:
                        sad_date = None
            
            # Generate new filename
            original_filename = file.filename
            file_extension = os.path.splitext(original_filename)[1] if '.' in original_filename else ''
            
            # Include SAD type in filename for returned documents
            sad_type_info = f"_{sad_type}" if status == 'returned' and sad_type else ""
            
            new_filename = secure_filename(f"{status}_BL:{bl_number}_{consignee}_{document_holder}{sad_type_info}{file_extension}")
            
            # Upload file to R2
            file_url = storage.upload_file(file, new_filename)
            
            # Get current user
            current_user = users.find_one({'_id': ObjectId(session['user_id'])})
            
            # Create document record
            document = {
                'bl_number': bl_number,
                'consignee': consignee,
                'declarant_company': declarant_company,
                'document_holder': document_holder,
                'document_holder_phone': document_holder_phone,
                'filename': new_filename,
                'file_path': file_url,
                'status': status,
                'version': 1,
                'upload_date': datetime.utcnow(),
                'user_id': ObjectId(session['user_id']),
                'uploader_username': current_user['username']
            }
            
            # Add SAD details if status is returned
            if status == 'returned':
                document['sad_number'] = sad_number
                document['sad_date'] = sad_date
                document['sad_type'] = sad_type
            
            result = documents.insert_one(document)
            
            # Check for existing documents with the same BL number
            existing_docs = list(documents.find({
                    'bl_number': bl_number,
                '_id': {'$ne': result.inserted_id},
                'paired_with': None  # Only look for unpaired documents
            }).sort('upload_date', 1))  # Sort by upload date to get oldest first
            
            # Handle document pairing
            if existing_docs:
                if len(existing_docs) >= 1:
                    # Pair with the oldest unpaired document with the same BL number
                    existing_doc = existing_docs[0]
                    
                    # Update both documents with paired information
                    documents.update_one(
                        {'_id': existing_doc['_id']},
                        {'$set': {
                            'paired_with': result.inserted_id,
                            'status': 'returned' if status == 'returned' else existing_doc['status']
                        }}
                    )
                    documents.update_one(
                        {'_id': result.inserted_id},
                        {'$set': {'paired_with': existing_doc['_id']}}
                    )
                    
                    # Send pairing notification
                    pair_message = f"""<b>Documents Paired</b>

Pairing Details:
- BL Number: <code>{bl_number}</code>
- Consignee: <code>{consignee}</code>
- Declarant Company: <code>{declarant_company}</code>
- Document Holder: <code>{document_holder}</code>
- First Doc ID: <code>{existing_doc['_id']}</code>
- Second Doc ID: <code>{result.inserted_id}</code>

Paired by: <b>{current_user['first_name']} {current_user['last_name']}</b>
Pair time: <code>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</code>"""
                    
                    send_telegram_notification(pair_message, 'doc_pair')
                    flash({'text': 'Document uploaded and paired successfully', 
                          'url': url_for('view_document', document_id=str(result.inserted_id))}, 'success')
                
                # Check if there are more than 2 documents with the same BL number
                total_docs_with_bl = documents.count_documents({'bl_number': bl_number})
                if total_docs_with_bl > 2:
                    # Send admin notification about multiple documents
                    admin_notification = f"""<b>⚠️ Multiple Documents Alert</b>

More than 2 documents found with the same BL number:
- BL Number: <code>{bl_number}</code>
- Consignee: <code>{consignee}</code>
- Declarant Company: <code>{declarant_company}</code>
- Document Holder: <code>{document_holder}</code>
- Total Documents: <code>{total_docs_with_bl}</code>

Latest Upload Details:
- Document ID: <code>{result.inserted_id}</code>
- Status: <code>{status}</code>
- Uploaded by: <b>{current_user['first_name']} {current_user['last_name']}</b>
- Upload time: <code>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</code>

Please review these documents to ensure proper handling."""
                    
                    # Send special notification to admins
                    send_telegram_notification(admin_notification, 'admin_alert')
                    
                    # Flash warning message to user
                    flash({
                        'text': 'Document uploaded and paired successfully. Note: Multiple documents with the same BL number detected. Admin has been notified.',
                        'url': url_for('view_document', document_id=str(result.inserted_id))
                    }, 'warning')
            
                else:
                    # No existing documents with this BL - normal upload notification
                    notification_message = f"""<b>New Document Uploaded</b>

Document Details:
- BL Number: <code>{bl_number}</code>
- Consignee: <code>{consignee}</code>
- Declarant Company: <code>{declarant_company}</code>
- Document Holder: <code>{document_holder}</code>
- Document Holder Phone: <code>{document_holder_phone}</code>
- Status: <code>{status}</code>
"""
                    # Add SAD information if returned
                    if status == 'returned':
                        notification_message += f"""- SAD Number: <code>{sad_number}</code>
- SAD Date: <code>{sad_date}</code>
"""
                    
                    notification_message += f"""- Filename: <code>{new_filename}</code>

Uploaded by: <b>{current_user['first_name']} {current_user['last_name']}</b>
Upload time: <code>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</code>"""
                    
                    send_telegram_notification(notification_message, 'new_doc')
                    flash({
                        'text': 'Document uploaded successfully',
                        'url': url_for('view_document', document_id=str(result.inserted_id))
                    }, 'success')
            
            return redirect(url_for('index'))
    
    return render_template('upload.html')

@app.route('/document/<document_id>/edit', methods=['GET', 'POST'])
@document_owner_required
def edit_document(document_id):
    document = documents.find_one({'_id': ObjectId(document_id)})
    
    # Get the referrer URL, default to document details if not available
    referrer = request.referrer if request.referrer and 'edit' not in request.referrer else url_for('view_document', document_id=document_id)
    
    if request.method == 'POST':
        # Get form data
        bl_number = request.form.get('bl_number')
        consignee = request.form.get('consignee')
        declarant_company = request.form.get('declarant_company', '')
        document_holder = request.form.get('document_holder')
        document_holder_phone = request.form.get('document_holder_phone')
        status = request.form.get('status')
        
        # Get SAD details if status is returned
        sad_number = None
        sad_date = None
        sad_type = None
        if status == 'returned':
            sad_number = request.form.get('sad_number')
            sad_date_str = request.form.get('sad_date')
            sad_type = request.form.get('sad_type')
            
            if sad_date_str:
                try:
                    sad_date = datetime.strptime(sad_date_str, '%Y-%m-%d')
                except ValueError:
                    sad_date = None
        else:
            # Set default values for pending documents
            sad_number = 'N/A'
            sad_date = 'N/A'
            sad_type = 'N/A'
        
        # Update document
        update_data = {
            'bl_number': bl_number,
            'consignee': consignee,
            'declarant_company': declarant_company,
            'document_holder': document_holder,
            'document_holder_phone': document_holder_phone,
            'status': status,
            'sad_number': sad_number,
            'sad_date': sad_date,
            'sad_type': sad_type
        }
        
        # Check if a new file was uploaded
        if 'document' in request.files and request.files['document'].filename != '':
            file = request.files['document']
            filename = secure_filename(file.filename)
            new_version = document['version'] + 1
            
            # Upload new version to R2
            file_url = storage.upload_file(
                file, 
                f'documents/{document_id}/v{new_version}/{filename}'
            )
            
            # Update document record with new file info
            new_version_data = {
                'version': new_version,
                'filename': filename,
                'file_path': file_url,
                'upload_date': datetime.utcnow(),
                'uploaded_by': ObjectId(session['user_id'])
            }
            
            update_data.update({
                        'version': new_version,
                        'filename': filename,
                        'file_path': file_url
            })
            
            # Add version history
            documents.update_one(
                {'_id': ObjectId(document_id)},
                {'$push': {'versions': new_version_data}}
            )
        
        # Update the document with all changes - use direct update without $unset
        documents.update_one(
            {'_id': ObjectId(document_id)},
            {'$set': update_data}
        )
        
        # Get current user for notification
        current_user = users.find_one({'_id': ObjectId(session['user_id'])})
        
        # Send update notification
        update_message = f"""<b>Document Updated</b>

Document Details:
- BL Number: <code>{bl_number}</code>
- Consignee: <code>{consignee}</code>
- Declarant Company: <code>{declarant_company}</code>
- Document Holder: <code>{document_holder}</code>
- Document Holder Phone: <code>{document_holder_phone}</code>
- Status: <code>{status}</code>
"""
        # Add SAD information if returned
        if status == 'returned':
            update_message += f"""- SAD Number: <code>{sad_number}</code>
- SAD Date: <code>{sad_date}</code>
- SAD Type: <code>{sad_type}</code>
"""
        
        update_message += f"""- Document ID: <code>{document_id}</code>

Updated by: <b>{current_user['first_name']} {current_user['last_name']}</b>
Update time: <code>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</code>"""
        
        send_telegram_notification(update_message, 'doc_update')
        
        flash('Document updated successfully', 'success')
        return redirect(url_for('view_document', document_id=document_id))
    
    return render_template('edit_document.html', document=document, back_url=referrer)

def get_file_type(filename):
    """Determine file type based on extension"""
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    if ext in ['pdf']:
        return 'pdf'
    elif ext in ['jpg', 'jpeg', 'png', 'gif']:
        return 'image'
    elif ext in ['txt', 'csv', 'md']:
        return 'text'
    elif ext in ['doc', 'docx']:
        return 'word'
    elif ext in ['xls', 'xlsx']:
        return 'excel'
    else:
        return 'other'

@app.route('/document/<document_id>/preview')
@login_required
def preview_document(document_id):
    try:
        document = documents.find_one({'_id': ObjectId(document_id)})
        if not document:
            flash({'text': 'Document not found', 'url': url_for('index')}, 'danger')
            return redirect(url_for('index'))
        
        # Check if user has permission to view this document
        user = users.find_one({'_id': ObjectId(session['user_id'])})
        if user['role'] not in ['admin', 'supervisor'] and str(document.get('user_id', '')) != session['user_id']:
            flash({'text': 'You do not have permission to view this document', 'url': url_for('index')}, 'danger')
            return redirect(url_for('index'))
        
        file_type = get_file_type(document['filename'])
        file_url = document['file_path']
        
        # Get the referrer URL, default to documents page if not available
        referrer = request.referrer if request.referrer and 'preview' not in request.referrer else url_for('search_documents')
        
        return render_template(
            'preview_document.html',
            document=document,
            file_type=file_type,
            file_url=file_url,
            back_url=referrer
        )
        
    except Exception as e:
        flash({'text': f'Error previewing document: {str(e)}', 'url': url_for('index')}, 'danger')
        return redirect(url_for('index'))

@app.route('/document/<document_id>')
@login_required
def view_document(document_id):
    document = documents.find_one({'_id': ObjectId(document_id)})
    if not document:
        flash('Document not found', 'danger')
        return redirect(url_for('index'))
    
    # Check if user has permission to view this document
    user = users.find_one({'_id': ObjectId(session['user_id'])})
    if user['role'] not in ['admin', 'supervisor'] and str(document.get('user_id', '')) != session['user_id']:
        flash('You do not have permission to view this document', 'danger')
        return redirect(url_for('index'))
    
    # Add uploader username
    try:
        uploader = users.find_one({'_id': document['user_id']})
        document['uploader_username'] = uploader['username'] if uploader else "Unknown"
    except:
        document['uploader_username'] = "Unknown"
    
    paired_document = None
    if document.get('paired_with'):
        paired_document = documents.find_one({'_id': document['paired_with']})
    
        # For regular users, check if they have permission to view the paired document
        if paired_document and user['role'] not in ['admin', 'supervisor'] and str(paired_document.get('user_id', '')) != session['user_id']:
            # If they don't have permission, don't show the paired document
            paired_document = None
            flash('You do not have permission to view the paired document', 'warning')
        
        # Add uploader username for paired document
        if paired_document:
            try:
                paired_uploader = users.find_one({'_id': paired_document['user_id']})
                paired_document['uploader_username'] = paired_uploader['username'] if paired_uploader else "Unknown"
            except:
                paired_document['uploader_username'] = "Unknown"
    
    # Get the referrer URL, default to documents page if not available
    referrer = request.referrer if request.referrer and 'document' not in request.referrer else url_for('search_documents')
    
    return render_template('document_details.html', document=document, paired_document=paired_document, back_url=referrer)

@app.route('/export', methods=['GET', 'POST'])
@supervisor_required
def export_menu():
    documents_list = []
    if request.method == 'POST':
        try:
            date_from = request.form.get('date_from')
            date_to = request.form.get('date_to')
            status = request.form.get('status')
            
            # Build query based on filters
            query = {}
            
            if date_from and date_to:
                try:
                    from_date = datetime.strptime(date_from, '%Y-%m-%d')
                    to_date = datetime.strptime(date_to, '%Y-%m-%d')
                    query['upload_date'] = {
                        '$gte': from_date,
                        '$lte': to_date + timedelta(days=1)  # Include the entire end date
                    }
                except ValueError:
                    flash({
                        'text': 'Invalid date format',
                        'url': url_for('export_menu')
                    }, 'danger')
                    return redirect(url_for('export_menu'))
            
            if status and status != 'all':
                query['status'] = status
            
            # Fetch filtered documents
            docs = list(documents.find(query).sort('upload_date', -1))
            
            if not docs:
                flash({
                    'text': 'No documents found matching the criteria',
                    'url': url_for('export_menu')
                }, 'warning')
                return redirect(url_for('export_menu'))
            
            # Prepare documents for display
            for doc in docs:
                try:
                    user = users.find_one({'_id': doc['user_id']})
                    doc['uploaded_by'] = user['username'] if user else 'Unknown'
                except Exception as e:
                    print(f"Error processing document {doc.get('_id')}: {str(e)}")
                    doc['uploaded_by'] = 'Unknown'
            
            documents_list = docs
            
        except Exception as e:
            flash({
                'text': f'Error preparing preview: {str(e)}',
                'url': url_for('export_menu')
            }, 'danger')
            return redirect(url_for('export_menu'))
    
    return render_template('export.html', documents=documents_list)

@app.route('/export/download', methods=['POST'])
@supervisor_required
def download_export():
    try:
        date_from = request.form.get('date_from')
        date_to = request.form.get('date_to')
        status = request.form.get('status')
        
        # Build query based on filters
        query = {}
        
        if date_from and date_to:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                to_date = datetime.strptime(date_to, '%Y-%m-%d')
                query['upload_date'] = {
                    '$gte': from_date,
                    '$lte': to_date + timedelta(days=1)
                }
            except ValueError:
                flash({
                    'text': 'Invalid date format',
                    'url': url_for('export_menu')
                }, 'danger')
                return redirect(url_for('export_menu'))
        
        if status and status != 'all':
            query['status'] = status
        
        # Fetch filtered documents
        docs = list(documents.find(query).sort('upload_date', -1))
        
        # Convert documents to pandas DataFrame
        data = []
        for doc in docs:
            try:
                user = users.find_one({'_id': doc['user_id']})
                
                # Convert ObjectId to string for serialization
                doc_id = str(doc['_id'])
                user_id = str(doc['user_id'])
                paired_with = str(doc.get('paired_with')) if doc.get('paired_with') else None
                
                # Format dates properly
                upload_date = doc['upload_date'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(doc['upload_date'], datetime) else str(doc['upload_date'])
                
                # Handle SAD date for returned documents
                sad_date = None
                if doc.get('sad_date') and doc['sad_date'] != 'N/A':
                    if isinstance(doc['sad_date'], datetime):
                        sad_date = doc['sad_date'].strftime('%Y-%m-%d')
                    else:
                        sad_date = str(doc['sad_date'])
                
                data_row = {
                    'Document ID': doc_id,
                    'BL Number': doc.get('bl_number', ''),
                    'Consignee': doc.get('consignee', ''),
                    'Declarant Company': doc.get('declarant_company', 'Not specified'),
                    'Document Holder': doc.get('document_holder', 'Not specified'),
                    'Document Holder Phone': doc.get('document_holder_phone', 'Not specified'),
                    'Status': doc.get('status', ''),
                    'Upload Date': upload_date,
                    'Version': doc.get('version', 1),
                    'Uploaded By': user['username'] if user else 'Unknown',
                    'File Path': doc.get('file_path', '')
                }
                
                # Add SAD fields
                if doc.get('status') == 'returned':
                    data_row['SAD Number'] = doc.get('sad_number', 'Not specified')
                    data_row['SAD Date'] = sad_date or 'Not specified'
                    data_row['SAD Type'] = doc.get('sad_type', 'Not specified')
                else:
                    data_row['SAD Number'] = 'N/A'
                    data_row['SAD Date'] = 'N/A'
                    data_row['SAD Type'] = 'N/A'
                
                data.append(data_row)
            except Exception as e:
                print(f"Error processing document {doc.get('_id')}: {str(e)}")
                continue
        
        if not data:
            flash({
                'text': 'No valid documents found to export',
                'url': url_for('export_menu')
            }, 'warning')
            return redirect(url_for('export_menu'))
        
        # Create DataFrame
        df = pd.DataFrame(data)
        
        # Create Excel file in memory
        output = io.BytesIO()
        
        # Make sure we have openpyxl installed
        try:
            import openpyxl
            writer_engine = 'openpyxl'
        except ImportError:
            # If openpyxl is not available, use xlsxwriter as fallback
            writer_engine = 'xlsxwriter'
            
        try:
            # Create Excel file with the available engine
            with pd.ExcelWriter(output, engine=writer_engine) as writer:
                df.to_excel(writer, sheet_name='Documents', index=False)
                
                # If using openpyxl, apply formatting
                if writer_engine == 'openpyxl':
                    workbook = writer.book
                    worksheet = writer.sheets['Documents']
                    
                    # Format the header row
                    for col_num, column_title in enumerate(df.columns, 1):
                        cell = worksheet.cell(row=1, column=col_num)
                        cell.font = openpyxl.styles.Font(bold=True)
                        cell.fill = openpyxl.styles.PatternFill(start_color="D3D3D3", end_color="D3D3D3", fill_type="solid")
                        
                        # Auto-adjust column width
                        column_width = max(len(str(column_title)) + 2, 12)
                        worksheet.column_dimensions[cell.column_letter].width = column_width
                
                # If using xlsxwriter, apply different formatting
                elif writer_engine == 'xlsxwriter':
                    workbook = writer.book
                    worksheet = writer.sheets['Documents']
                    
                    # Format header
                    header_format = workbook.add_format({
                        'bold': True,
                        'bg_color': '#D3D3D3'
                    })
                    
                    # Apply header format
                    for col_num, column_title in enumerate(df.columns):
                        worksheet.write(0, col_num, column_title, header_format)
                        # Set column width
                        worksheet.set_column(col_num, col_num, max(len(str(column_title)) + 2, 12))
        
        except Exception as e:
            print(f"Error creating Excel file: {str(e)}")
            flash({
                'text': f'Error creating Excel file: {str(e)}',
                'url': url_for('export_menu')
            }, 'danger')
            return redirect(url_for('export_menu'))
        
        # Reset file pointer to beginning
        output.seek(0)
        
        # Generate timestamp for filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'document_report_{timestamp}.xlsx'
        
        # Send file to user
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        print(f"Export error: {str(e)}")
        flash({
            'text': f'Export failed: {str(e)}',
            'url': url_for('export_menu')
        }, 'danger')
        return redirect(url_for('export_menu'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if username already exists
        if users.find_one({'username': username}):
            flash('Username already exists. Please choose another.', 'danger')
            return redirect(url_for('signup'))
        
        # Check if email already exists
        if users.find_one({'email': email}):
            flash('Email already registered. Please login or use a different email.', 'danger')
            return redirect(url_for('signup'))
        
        # Create new user
        hashed_password = generate_password_hash(password)
        
        # Check if this is the first user (who becomes admin)
        is_first_user = users.count_documents({}) == 0
        
        new_user = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'username': username,
            'password': hashed_password,
            'role': 'admin' if is_first_user else 'user',  # First user becomes admin
            'created_at': datetime.utcnow(),
            'status': 'active' if is_first_user else 'pending'  # First user is active, others pending
        }
        
        result = users.insert_one(new_user)
        
        # If this is the first admin, mark them as the first admin
        if is_first_user:
            users.update_one(
                {'_id': result.inserted_id},
                {'$set': {'is_first_admin': True}}
            )
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            # For regular users, redirect to pending approval page
            session['pending_user_id'] = str(result.inserted_id)
            session['pending_username'] = username
            
            # Send notification to admins about new user registration
            admin_notification = f"""<b>New User Registration</b>

User Details:
- Username: <code>{username}</code>
- Name: <code>{first_name} {last_name}</code>
- Email: <code>{email}</code>
- Registration time: <code>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</code>

This user is pending approval. Please review and approve if appropriate."""
            
            send_telegram_notification(admin_notification, 'admin_alert')
            
            flash('Your account has been created and is pending approval by an administrator.', 'info')
            return redirect(url_for('pending_approval'))
    
    return render_template('signup.html')

# Add Telegram management route for admins
@app.route('/telegram/subscriptions')
@admin_required
def telegram_subscriptions_list():
    subs = list(telegram_subscriptions.find())
    return render_template('telegram_subscriptions.html', subscriptions=subs)

# Add new routes for account settings
@app.route('/account/settings', methods=['GET', 'POST'])
@login_required
def account_settings():
    user = users.find_one({'_id': ObjectId(session['user_id'])})
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        
        if not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('account_settings'))
        
        # Update user information
        update_data = {
            'first_name': request.form.get('first_name'),
            'last_name': request.form.get('last_name'),
            'phone': request.form.get('phone')
        }
        
        # Update password if provided
        new_password = request.form.get('new_password')
        if new_password:
            if new_password != request.form.get('confirm_password'):
                flash('New passwords do not match', 'danger')
                return redirect(url_for('account_settings'))
            
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return redirect(url_for('account_settings'))
            
            update_data['password'] = generate_password_hash(new_password)
        
        users.update_one(
            {'_id': ObjectId(session['user_id'])},
            {'$set': update_data}
        )
        
        # Update session name
        session['name'] = f"{update_data['first_name']} {update_data['last_name']}"
        
        flash('Account settings updated successfully', 'success')
        return redirect(url_for('account_settings'))
    
    return render_template('account_settings.html', user=user)

@app.route('/account/telegram', methods=['GET', 'POST'])
@login_required
def telegram_settings():
    user = users.find_one({'_id': ObjectId(session['user_id'])})
    
    # Check if user has Telegram connection
    telegram_sub = telegram_subscriptions.find_one({
        'user_id': ObjectId(session['user_id']),
        'active': True
    })
    
    # Get or initialize notification settings
    settings = user.get('telegram_settings', {
        'notify_new_doc': True,
        'notify_doc_update': True,
        'notify_doc_pair': True
    })
    
    if request.method == 'POST':
        # Update notification settings
        settings = {
            'notify_new_doc': 'notify_new_doc' in request.form,
            'notify_doc_update': 'notify_doc_update' in request.form,
            'notify_doc_pair': 'notify_doc_pair' in request.form
        }
        
        users.update_one(
            {'_id': ObjectId(session['user_id'])},
            {'$set': {'telegram_settings': settings}}
        )
        
        flash('Notification settings updated successfully', 'success')
        return redirect(url_for('telegram_settings'))
    
    return render_template('telegram_settings.html',
                         telegram_status=bool(telegram_sub),
                         settings=settings)

@app.route('/reset_database')
def reset_database():
    try:
        # Drop all collections
        users.drop()
        documents.drop()
        telegram_subscriptions.drop()
        
        # Remove the automatic first admin creation
        app.config['FIRST_ADMIN_CREATED'] = False
        
        flash('Database has been reset. Please sign up as the first admin.', 'success')
        return redirect(url_for('signup'))
    except Exception as e:
        flash(f'Error resetting database: {str(e)}', 'danger')
        return redirect(url_for('login'))

@app.route('/telegram/qr-code')
@login_required
def telegram_qr_code():
    """Generate QR code for Telegram bot link"""
    bot_username = app.config['TELEGRAM_BOT_USERNAME']
    telegram_url = f"https://t.me/{bot_username}"
    
    # Create QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(telegram_url)
    qr.make(fit=True)
    
    # Create image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save image to bytes
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    
    return send_file(
        img_bytes,
        mimetype='image/png',
        download_name='telegram_bot_qr.png'
    )

@app.route('/export_report')
@supervisor_required
def export_report():
    # Redirect to the export menu page
    return redirect(url_for('export_menu'))

@app.route('/pair-documents/<doc1_id>/<doc2_id>')
@supervisor_required
def pair_specific_documents(doc1_id, doc2_id):
    """Pair two specific documents by their IDs"""
    try:
        doc1 = documents.find_one({'_id': ObjectId(doc1_id)})
        doc2 = documents.find_one({'_id': ObjectId(doc2_id)})
        
        if not doc1 or not doc2:
            flash('One or both documents not found', 'danger')
            return redirect(url_for('search_documents'))
        
        # Check if either document is already paired
        if doc1.get('paired_with') or doc2.get('paired_with'):
            flash('One or both documents are already paired with other documents', 'warning')
            return redirect(url_for('search_documents'))
        
        # Update both documents with paired information
        documents.update_one(
            {'_id': ObjectId(doc1_id)},
            {'$set': {
                'paired_with': ObjectId(doc2_id),
                'status': 'returned' if doc2['status'] == 'returned' else doc1['status']
            }}
        )
        documents.update_one(
            {'_id': ObjectId(doc2_id)},
            {'$set': {'paired_with': ObjectId(doc1_id)}}
        )
        
        # Get current user for notification
        current_user = users.find_one({'_id': ObjectId(session['user_id'])})
        
        # Send pairing notification
        pair_message = f"""<b>Documents Manually Paired</b>

Pairing Details:
- BL Numbers: <code>{doc1['bl_number']}</code> and <code>{doc2['bl_number']}</code>
- First Doc ID: <code>{doc1_id}</code>
- Second Doc ID: <code>{doc2_id}</code>

Paired by: <b>{current_user['first_name']} {current_user['last_name']}</b>
Pair time: <code>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</code>"""
        
        send_telegram_notification(pair_message, 'doc_pair')
        
        flash('Documents paired successfully', 'success')
        return redirect(url_for('view_document', document_id=doc1_id))
    
    except Exception as e:
        flash(f'Error pairing documents: {str(e)}', 'danger')
        return redirect(url_for('search_documents'))

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search_documents():
    documents_list = []
    paired_docs = {}
    search_performed = False
    
    # Base query
    query = {}
    
    # Add user restriction for regular users
    user = users.find_one({'_id': ObjectId(session['user_id'])})
    if user['role'] not in ['admin', 'supervisor']:
        query['user_id'] = ObjectId(session['user_id'])
    
    if request.method == 'POST':
        search_performed = True
        bl_number = request.form.get('bl_number')
        consignee = request.form.get('consignee')
        declarant_company = request.form.get('declarant_company')
        document_holder = request.form.get('document_holder')
        sad_number = request.form.get('sad_number')
        
        # Get the search field and value from the dropdown approach
        search_field = request.form.get('search_field')
        search_value = request.form.get('search_value')
        
        # If using the dropdown search and a value is provided, update the corresponding field
        if search_field and search_value:
            if search_field == 'bl_number':
                bl_number = search_value
            elif search_field == 'consignee':
                consignee = search_value
            elif search_field == 'declarant_company':
                declarant_company = search_value
            elif search_field == 'document_holder':
                document_holder = search_value
            elif search_field == 'sad_number':
                sad_number = search_value
        
        if bl_number:
            query['bl_number'] = {'$regex': bl_number, '$options': 'i'}
        
        if consignee:
            query['consignee'] = {'$regex': consignee, '$options': 'i'}
            
        if declarant_company:
            query['declarant_company'] = {'$regex': declarant_company, '$options': 'i'}
            
        if document_holder:
            query['document_holder'] = {'$regex': document_holder, '$options': 'i'}
            
        if sad_number:
            query['sad_number'] = {'$regex': sad_number, '$options': 'i'}
    
    # Get all matching documents
    documents_list = list(documents.find(query).sort('upload_date', -1))
    
    # Get paired documents information
    for doc in documents_list:
        if doc.get('paired_with'):
            paired_doc = documents.find_one({'_id': doc['paired_with']})
            # For regular users, only include paired documents they own
            if paired_doc:
                if user['role'] in ['admin', 'supervisor'] or str(paired_doc.get('user_id', '')) == session['user_id']:
                    paired_docs[doc['_id']] = paired_doc
        
        # Add uploader information
        try:
            uploader = users.find_one({'_id': doc['user_id']})
            doc['uploader_name'] = uploader['username'] if uploader else "Unknown"
        except:
            doc['uploader_name'] = "Unknown"
    
    return render_template('documents.html',
                         documents=documents_list,
                         paired_docs=paired_docs,
                         search_performed=search_performed,
                         search_values={
                             'bl_number': request.form.get('bl_number', ''),
                             'consignee': request.form.get('consignee', ''),
                             'declarant_company': request.form.get('declarant_company', ''),
                             'document_holder': request.form.get('document_holder', ''),
                             'sad_number': request.form.get('sad_number', ''),
                             'search_field': request.form.get('search_field', 'bl_number'),
                             'search_value': request.form.get('search_value', '')
                         })

@app.route('/document/<document_id>/versions')
@login_required
def document_versions(document_id):
    document = documents.find_one({'_id': ObjectId(document_id)})
    if not document:
        flash('Document not found', 'danger')
        return redirect(url_for('index'))
    
    # Check if user has permission to view this document
    user = users.find_one({'_id': ObjectId(session['user_id'])})
    if user['role'] not in ['admin', 'supervisor'] and str(document.get('user_id', '')) != session['user_id']:
        flash('You do not have permission to access this document', 'danger')
        return redirect(url_for('index'))
    
    # Add file type information for each version
    if 'versions' in document:
        for version in document['versions']:
            version['file_type'] = get_file_type(version['filename'])
    
    # Get the referrer URL, default to document details if not available
    referrer = request.referrer if request.referrer and 'versions' not in request.referrer else url_for('view_document', document_id=document_id)
    
    return render_template('document_versions.html', document=document, back_url=referrer)

# Add context processor to make pending users count available to all templates
@app.context_processor
def inject_pending_users_count():
    context = {'pending_users_count': 0}
    
    # Only count pending users if the current user is an admin
    if 'user_id' in session and 'role' in session and session['role'] == 'admin':
        try:
            context['pending_users_count'] = users.count_documents({"status": "pending"})
        except Exception as e:
            print(f"Error counting pending users: {e}")
    
    return context

if __name__ == '__main__':
    app.run(debug=True)
