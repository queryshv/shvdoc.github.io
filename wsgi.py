import sys
import os

# Add your project directory to Python path
path = '/home/queryshv11/telegram-bot'  # Update this to your actual username
if path not in sys.path:
    sys.path.append(path)

# Add virtualenv site-packages
VIRTUALENV_PATH = '/home/queryshv11/.virtualenvs/mybot/lib/python3.10/site-packages'
if VIRTUALENV_PATH not in sys.path:
    sys.path.append(VIRTUALENV_PATH)

from telegram_bot import app as application 