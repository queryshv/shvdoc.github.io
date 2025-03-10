from flask import Flask, request, jsonify, send_file
from pymongo import MongoClient
from datetime import datetime, timedelta
import requests
import os
import logging
import certifi
import dns.resolver
import sys
import pandas as pd
import io

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Bot configuration
BOT_USERNAME = "shvdoc_bot"

# Read token from file
try:
    with open('token.txt', 'r') as file:
        TELEGRAM_BOT_TOKEN = file.read().strip()
        logger.info("Bot token loaded successfully")
except FileNotFoundError:
    logger.error("Error: token.txt file not found!")
    TELEGRAM_BOT_TOKEN = ""

# Configuration
MONGODB_URI = "mongodb://shvdoc:Sovathna%40123@ac-yvwzwpj-shard-00-00.0tjt0.mongodb.net:27017,ac-yvwzwpj-shard-00-01.0tjt0.mongodb.net:27017,ac-yvwzwpj-shard-00-02.0tjt0.mongodb.net:27017/shvdoc?ssl=true&replicaSet=atlas-qc7mj6-shard-0&authSource=admin"
DB_NAME = "shvdoc"

# MongoDB configuration
try:
    # Configure MongoDB client with explicit DNS and SSL settings
    client = MongoClient(
        MONGODB_URI,
        tlsCAFile=certifi.where(),
        connect=True,
        serverSelectionTimeoutMS=5000
    )
    
    # Force a connection to verify it works
    db = client[DB_NAME]
    telegram_subscriptions = db.telegram_subscriptions
    users = db.users
    client.admin.command('ping')
    logger.info("Connected to MongoDB successfully!")
except Exception as e:
    logger.error(f"MongoDB connection error: {e}")
    # Log more details about the error
    logger.error(f"MongoDB URI: {MONGODB_URI}")
    logger.error(f"Python path: {sys.path}")
    logger.error(f"Current working directory: {os.getcwd()}")

def send_telegram_message(chat_id, text, parse_mode='HTML', notification_type='info'):
    """Helper function to send Telegram messages with compact formatting"""
    try:
        # Color coding for different message types
        colors = {
            'success': '🟢',
            'info': 'ℹ️',
            'warning': '⚠️',
            'error': '🔴'
        }
        
        # Add horizontal line for visual separation
        formatted_text = (
            f"{colors.get(notification_type, 'ℹ️')} {text}\n"
            "──────────────"
        )
        
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {
            'chat_id': chat_id,
            'text': formatted_text,
            'parse_mode': parse_mode,
            'disable_notification': False,
            'protect_content': True
        }
        response = requests.post(url, json=data)
        if response.ok:
            logger.info(f"Message sent successfully to chat_id: {chat_id}")
        else:
            logger.error(f"Failed to send message: {response.text}")
        return response.json()
    except Exception as e:
        logger.error(f"Error sending telegram message: {e}")
        return None

def send_notification_to_all(message, notification_type='new_doc'):
    """Send notification to all subscribed users with compact styling"""
    type_emojis = {
        'new_doc': '📄',
        'doc_update': '🔄',
        'doc_pair': '🔗'
    }
    emoji = type_emojis.get(notification_type, 'ℹ️')
    
    # Format notification in a compact way
    formatted_message = (
        f"<b>{emoji} New Alert</b>\n"
        "──────────────\n"
        f"{message}"
    )
    
    subscriptions = telegram_subscriptions.find({'active': True})
    for sub in subscriptions:
        try:
            user = users.find_one({'_id': sub.get('user_id')})
            if user and user.get('telegram_settings', {}).get(f'notify_{notification_type}', True):
                send_telegram_message(sub['chat_id'], formatted_message, notification_type='info')
        except Exception as e:
            logger.error(f"Error sending notification: {e}")

def get_help_message():
    """Get the help message with available commands in a compact format"""
    return (
        "📱 <b>SHV Doc Management</b>\n"
        "──────────────\n"
        "<b>Commands:</b>\n"
        "▫️ /start - Subscribe\n"
        "▫️ /stop - Unsubscribe\n"
        "▫️ /help - Show help\n"
        "▫️ /status - Check settings\n"
        "▫️ /export - Export reports\n"
        "──────────────\n"
        "<b>Export Options:</b>\n"
        "• /export today\n"
        "• /export week\n"
        "• /export month\n"
        "• /export pending\n"
        "• /export returned"
    )

def generate_report(time_filter=None, status_filter=None):
    """Generate report based on filters"""
    query = {}
    
    # Apply time filter
    if time_filter:
        now = datetime.utcnow()
        if time_filter == 'today':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif time_filter == 'week':
            start_date = now - timedelta(days=7)
        elif time_filter == 'month':
            start_date = now - timedelta(days=30)
        query['upload_date'] = {'$gte': start_date}
    
    # Apply status filter
    if status_filter:
        query['status'] = status_filter
    
    # Fetch documents
    docs = list(db.documents.find(query))
    
    if not docs:
        return None
    
    # Convert to DataFrame
    data = []
    for doc in docs:
        user = users.find_one({'_id': doc['user_id']})
        data.append({
            'BL Number': doc['bl_number'],
            'Consignee': doc['consignee'],
            'Status': doc['status'],
            'Upload Date': doc['upload_date'].strftime('%Y-%m-%d %H:%M'),
            'Version': doc['version'],
            'Uploaded By': f"{user['first_name']} {user['last_name']}" if user else 'Unknown',
            'File Path': doc['file_path']
        })
    
    df = pd.DataFrame(data)
    
    # Create Excel file in memory
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Documents', index=False)
    
    output.seek(0)
    return output

@app.route(f'/{TELEGRAM_BOT_TOKEN}', methods=['POST'])
def webhook():
    """Handle incoming webhook updates from Telegram"""
    data = request.get_json()
    
    if 'message' not in data:
        return jsonify({'status': 'ok'})
    
    message = data['message']
    chat_id = message['chat']['id']
    text = message.get('text', '')
    
    # Check if user is admin before allowing export
    user = users.find_one({'telegram_chat_id': chat_id, 'role': {'$in': ['admin', 'supervisor']}})
    
    if text.startswith('/export'):
        if not user:
            send_telegram_message(
                chat_id,
                "❌ You don't have permission to export reports.\nContact admin for access.",
                notification_type='error'
            )
            return jsonify({'status': 'ok'})
        
        # Parse export command
        parts = text.split()
        if len(parts) == 1:
            # Show export options
            export_help = (
                "<b>📊 Export Options</b>\n"
                "──────────────\n"
                "<b>Time Filters:</b>\n"
                "• /export today - Today's documents\n"
                "• /export week - Last 7 days\n"
                "• /export month - Last 30 days\n\n"
                "<b>Status Filters:</b>\n"
                "• /export pending - Pending documents\n"
                "• /export returned - Returned documents\n"
                "──────────────"
            )
            send_telegram_message(chat_id, export_help, notification_type='info')
            return jsonify({'status': 'ok'})
        
        filter_type = parts[1].lower()
        
        # Generate report based on filter
        if filter_type in ['today', 'week', 'month']:
            output = generate_report(time_filter=filter_type)
        elif filter_type in ['pending', 'returned']:
            output = generate_report(status_filter=filter_type)
        else:
            send_telegram_message(
                chat_id,
                "❌ Invalid export option.\nUse /export to see available options.",
                notification_type='error'
            )
            return jsonify({'status': 'ok'})
        
        if output:
            # Send Excel file
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            files = {
                'document': (
                    f'document_report_{filter_type}_{timestamp}.xlsx',
                    output,
                    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                )
            }
            response = requests.post(url, data={'chat_id': chat_id}, files=files)
            
            if response.ok:
                send_telegram_message(
                    chat_id,
                    f"✅ Report generated successfully for: {filter_type}",
                    notification_type='success'
                )
            else:
                send_telegram_message(
                    chat_id,
                    "❌ Failed to send report.\nPlease try again.",
                    notification_type='error'
                )
        else:
            send_telegram_message(
                chat_id,
                f"ℹ️ No documents found for: {filter_type}",
                notification_type='info'
            )
        
        return jsonify({'status': 'ok'})
    
    if text == '/start':
        existing = telegram_subscriptions.find_one({'chat_id': chat_id})
        if existing:
            telegram_subscriptions.update_one(
                {'chat_id': chat_id},
                {'$set': {'active': True}}
            )
            welcome_back = (
                "<b>Welcome Back! 👋</b>\n\n"
                "<b>Notifications Active:</b>\n"
                "✓ New uploads\n"
                "✓ Updates\n"
                "✓ Pairing\n\n"
                "📌 /help - See commands\n"
                "⚠️ /stop - Unsubscribe"
            )
            send_telegram_message(chat_id, welcome_back, notification_type='success')
        else:
            telegram_subscriptions.insert_one({
                'chat_id': chat_id,
                'username': message['from'].get('username'),
                'first_name': message['from'].get('first_name'),
                'last_name': message['from'].get('last_name'),
                'active': True,
                'subscribed_at': datetime.utcnow()
            })
            welcome_new = (
                "<b>Welcome! 🎉</b>\n\n"
                "<b>Notifications Active:</b>\n"
                "✓ New uploads\n"
                "✓ Updates\n"
                "✓ Pairing\n\n"
                "📌 /help - See commands\n"
                "⚠️ /stop - Unsubscribe"
            )
            send_telegram_message(chat_id, welcome_new, notification_type='success')
    
    elif text == '/stop':
        telegram_subscriptions.update_one(
            {'chat_id': chat_id},
            {'$set': {'active': False}}
        )
        response = (
            "<b>Notifications Paused ⏸</b>\n\n"
            "You will no longer receive notifications.\n"
            "Use /start to resubscribe at any time."
        )
        send_telegram_message(chat_id, response, notification_type='warning')
    
    elif text == '/help':
        send_telegram_message(chat_id, get_help_message(), notification_type='info')
    
    elif text == '/status':
        sub = telegram_subscriptions.find_one({'chat_id': chat_id})
        if sub and sub.get('active'):
            status = (
                "<b>Status 📊</b>\n\n"
                "✅ Notifications: ON\n"
                "✅ New docs: ON\n"
                "✅ Updates: ON\n"
                "✅ Pairing: ON\n\n"
                "⚠️ /stop - Unsubscribe"
            )
            notification_type = 'success'
        else:
            status = (
                "<b>Status 📊</b>\n\n"
                "❌ Notifications: OFF\n\n"
                "📌 /start - Subscribe"
            )
            notification_type = 'warning'
        send_telegram_message(chat_id, status, notification_type=notification_type)
    
    else:
        # Handle unknown commands or regular messages
        if text.startswith('/'):
            send_telegram_message(
                chat_id,
                "❌ Unknown command\nUse /help to see available commands.",
                notification_type='error'
            )
        else:
            send_telegram_message(chat_id, get_help_message(), notification_type='info')
    
    return jsonify({'status': 'ok'})

@app.route('/notify', methods=['POST'])
def notify():
    """Endpoint to send notifications from the main application"""
    data = request.get_json()
    if not data or 'message' not in data or 'type' not in data:
        return jsonify({'error': 'Invalid request'}), 400
    
    send_notification_to_all(data['message'], data['type'])
    return jsonify({'status': 'ok'})

@app.route('/set_webhook')
def set_webhook():
    """Helper endpoint to set up the webhook"""
    try:
        base_url = request.url_root.rstrip('/')
        webhook_url = f"{base_url}/{TELEGRAM_BOT_TOKEN}"
        
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/setWebhook"
        response = requests.post(url, json={'url': webhook_url})
        
        if response.status_code == 200:
            return jsonify({
                'status': 'success',
                'message': 'Webhook set successfully',
                'webhook_url': webhook_url,
                'telegram_response': response.json()
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to set webhook',
                'telegram_response': response.json()
            }), 400
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/')
def index():
    """Simple index page to verify the bot is running"""
    logger.info("Bot health check - Bot is running")
    return f"SHV Document Management Telegram Bot (@{BOT_USERNAME}) is running!"

# Add startup message with correct username
logger.info("=== SHV Document Management Telegram Bot Started ===")
logger.info(f"Bot Username: @{BOT_USERNAME}")

# Remove the if __name__ == '__main__' block
# The bot will be run by the WSGI server instead 