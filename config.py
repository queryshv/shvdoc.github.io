import os
import json
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.server_api import ServerApi

# Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration class"""
    
    # Load R2 credentials from JSON file
    R2_CREDENTIALS_PATH = os.path.join('credentials', 'r2_credentials.json')
    try:
        with open(R2_CREDENTIALS_PATH, 'r') as f:
            r2_credentials = json.load(f)
    except FileNotFoundError:
        r2_credentials = {}
    
    # Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # MongoDB Configuration
    MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
    MONGODB_DB_NAME = os.getenv('MONGODB_DB_NAME', 'shvdoc')
    MONGODB_CLIENT_OPTIONS = {'server_api': ServerApi('1')}
    
    # Cloudflare R2 Configuration
    R2_ACCOUNT_ID = r2_credentials.get('account_id') or os.getenv('R2_ACCOUNT_ID')
    R2_ACCESS_KEY_ID = r2_credentials.get('access_key_id') or os.getenv('R2_ACCESS_KEY_ID')
    R2_SECRET_ACCESS_KEY = r2_credentials.get('secret_access_key') or os.getenv('R2_SECRET_ACCESS_KEY')
    R2_BUCKET_NAME = r2_credentials.get('bucket_name') or os.getenv('R2_BUCKET_NAME')
    R2_PUBLIC_URL = r2_credentials.get('public_url') or os.getenv('R2_PUBLIC_URL')
    
    # R2 Endpoint URL - Using the jurisdiction-specific endpoint
    R2_ENDPOINT_URL = 'https://2fc1dca37dbede479ae1c5132ec7628f.r2.cloudflarestorage.com'
    
    # Telegram Bot Configuration
    TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
    TELEGRAM_BOT_USERNAME = os.getenv('TELEGRAM_BOT_USERNAME', 'shvdoc_bot')
    TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
    
    # File Upload Configuration
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB in bytes
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png'}
    
    @staticmethod
    def is_valid_extension(filename):
        """Check if file extension is allowed"""
        return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS 