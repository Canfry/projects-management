import os
from datetime import timedelta

def config(app):
    # Configure the session
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    app.config.from_object(__name__)
    # Security for HTTPS
    app.config['SESSION_COOKIE_SECURE'] = True
    # Prevent malicious scripts
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)