# Document Management System

A web-based document management system with user roles, file versioning, and Telegram notifications.

## Features

- User authentication and role-based access control
- Document upload and versioning
- Telegram notifications
- MongoDB database integration
- Google Cloud Storage for file storage
- Excel report export
- Secure credential management

## Prerequisites

- Python 3.8 or higher
- MongoDB 4.4 or higher
- Google Cloud account with Storage enabled
- Telegram Bot Token
- pip (Python package installer)

## Installation

### Standard Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd document-management
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

### Troubleshooting Installation Issues

If you encounter connection errors with pip, try these solutions:

1. Using alternative PyPI mirrors:
```bash
# Using an alternative mirror
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
# or
pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/
```

2. Using offline installation:
```bash
# Download wheels on a machine with internet access
pip download -r requirements.txt -d ./wheels

# Copy the wheels folder to the target machine and install
pip install --no-index --find-links wheels -r requirements.txt
```

3. Configure pip to use a proxy:
```bash
# Set HTTP proxy
set HTTP_PROXY=http://your-proxy:port
set HTTPS_PROXY=http://your-proxy:port

# Or in Linux/Mac
export HTTP_PROXY=http://your-proxy:port
export HTTPS_PROXY=http://your-proxy:port
```

4. Using direct download links:
If you're still having issues, you can manually download and install the required packages from:
- https://pypi.org/simple/flask/
- https://pypi.org/simple/pymongo/
- https://pypi.org/simple/google-cloud-storage/
(Download the appropriate .whl files for your Python version and OS)

5. Verify your network settings:
```bash
# Test connection to PyPI
ping pypi.org

# Check DNS resolution
nslookup pypi.org

# Clear pip cache
pip cache purge
```

### Post-Installation Setup

1. Set up environment variables:
```bash
# Copy example environment file
cp .env.example .env

# Edit .env file with your credentials
nano .env
```

2. Set up Google Cloud credentials:
- Download your service account key JSON file
- Update the GOOGLE_APPLICATION_CREDENTIALS path in .env

3. Set up Telegram Bot:
- Create a bot using BotFather
- Copy the bot token to .env
- Set up webhook URL

## Configuration

Update the following in your .env file:

```env
# Flask Configuration
FLASK_SECRET_KEY=your-secure-secret-key
FLASK_DEBUG=False  # Set to True for development

# MongoDB Configuration
MONGODB_URI=your-mongodb-uri
MONGODB_DB_NAME=document_management

# Google Cloud Storage Configuration
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_CLOUD_BUCKET=your-bucket-name
GOOGLE_APPLICATION_CREDENTIALS=path/to/credentials.json

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN=your-bot-token
TELEGRAM_BOT_USERNAME=your-bot-username
```

## Running the Application

1. Start the application:
```bash
python app.py
```

2. Access the application:
- Open a web browser
- Navigate to http://localhost:5000
- Default admin credentials:
  - Email: admin@example.com
  - Password: admin

## Development

For development work:
```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
pytest

# Format code
black .

# Check code style
flake8
```

## Security Notes

1. Change the default admin password immediately after first login
2. Keep your .env file secure and never commit it to version control
3. Regularly rotate your API keys and tokens
4. Use HTTPS in production
5. Keep your dependencies updated

## File Upload Limits

- Maximum file size: 16MB
- Allowed file types: pdf, doc, docx, txt, jpg, jpeg, png
- To modify these limits, update the .env file

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 