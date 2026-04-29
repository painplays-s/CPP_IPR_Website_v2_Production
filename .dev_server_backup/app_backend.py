#!/usr/bin/env python3
"""
Backend Server – Admin Panel + Analytics
Provides the CMS for managing content (CRUD + file uploads) AND analytics.
Runs on 0.0.0.0:5001 (HTTP) – relies on its own login for security.
Serves all root static files (UI, assets, pages) so admin pages display correctly.
"""

import sys
from pathlib import Path
from flask import Flask, redirect, url_for, send_from_directory, abort, request, g, session, jsonify
from datetime import datetime
import hashlib
import json
import os
import logging
from logging.handlers import RotatingFileHandler

# Add backend directory to path so we can import its modules
BACKEND_DIR = Path(__file__).parent / 'backend'
ROOT_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(BACKEND_DIR))

from config import SECRET_KEY
from models.database import ensure_db_and_migrations

# Import all admin blueprints
from routes.admin_auth import admin_auth
from routes.admin_home import admin_home_bp
from routes.admin_carousal import admin_carousal_bp
from routes.admin_notice import admin_notice
from routes.admin_research import admin_research
from routes.admin_publication import admin_publication
from routes.admin_forms_links import admin_forms_links_bp
from routes.admin_people import admin_people_bp
from routes.admin_tender import admin_tender_bp
from routes.admin_advertisement import admin_advertisement_bp
from routes.public_api import public_api
from routes.error import register_error_handlers
from routes.admin_analytics import admin_analytics

# =====================================================
# ANALYTICS DIRECTORY SETUP
# =====================================================

# Create analytics directory in root (instead of logs)
ANALYTICS_DIR = Path(__file__).parent / 'analytics'
ANALYTICS_DIR.mkdir(exist_ok=True)

# Backend log files in analytics directory
BACKEND_ACCESS_LOG = ANALYTICS_DIR / 'backend_access.log'
BACKEND_AUTH_LOG = ANALYTICS_DIR / 'backend_auth.log'
BACKEND_SECURITY_LOG = ANALYTICS_DIR / 'backend_security.log'
BACKEND_ERROR_LOG = ANALYTICS_DIR / 'backend_error.log'

# Create log files if they don't exist
for log_file in [BACKEND_ACCESS_LOG, BACKEND_AUTH_LOG, BACKEND_SECURITY_LOG, BACKEND_ERROR_LOG]:
    if not log_file.exists():
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(f"# Backend log file created on {datetime.now().isoformat()}\n")
        print(f"✅ Created: {log_file.name}")

# =====================================================
# SECURITY LOGGING CONFIGURATION
# =====================================================

class SecurityLogger:
    """Custom security logger for tracking all requests and security events"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        # Use analytics directory instead of logs
        if not ANALYTICS_DIR.exists():
            ANALYTICS_DIR.mkdir(parents=True, exist_ok=True)
        
        # ===== BACKEND ACCESS LOG =====
        access_handler = RotatingFileHandler(
            BACKEND_ACCESS_LOG, 
            maxBytes=10_485_760,  # 10MB
            backupCount=30,
            encoding='utf-8'
        )
        access_handler.setLevel(logging.INFO)
        access_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        access_handler.setFormatter(access_formatter)
        
        access_logger = logging.getLogger('backend_access')
        access_logger.setLevel(logging.INFO)
        access_logger.addHandler(access_handler)
        access_logger.propagate = False
        app.access_logger = access_logger
        
        # ===== BACKEND AUTH LOG =====
        auth_handler = RotatingFileHandler(
            BACKEND_AUTH_LOG,
            maxBytes=10_485_760,
            backupCount=30,
            encoding='utf-8'
        )
        auth_handler.setLevel(logging.INFO)
        auth_formatter = logging.Formatter(
            '%(asctime)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        auth_handler.setFormatter(auth_formatter)
        
        auth_logger = logging.getLogger('backend_auth')
        auth_logger.setLevel(logging.INFO)
        auth_logger.addHandler(auth_handler)
        auth_logger.propagate = False
        app.auth_logger = auth_logger
        
        # ===== BACKEND SECURITY LOG =====
        security_handler = RotatingFileHandler(
            BACKEND_SECURITY_LOG,
            maxBytes=10_485_760,
            backupCount=30,
            encoding='utf-8'
        )
        security_handler.setLevel(logging.INFO)
        security_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        security_handler.setFormatter(security_formatter)
        
        security_logger = logging.getLogger('backend_security')
        security_logger.setLevel(logging.INFO)
        security_logger.addHandler(security_handler)
        security_logger.propagate = False
        app.security_logger = security_logger
        
        # ===== BACKEND ERROR LOG =====
        error_handler = RotatingFileHandler(
            BACKEND_ERROR_LOG,
            maxBytes=10_485_760,
            backupCount=30,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s | %(pathname)s:%(lineno)d',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        error_handler.setFormatter(error_formatter)
        
        error_logger = logging.getLogger('backend_error')
        error_logger.setLevel(logging.ERROR)
        error_logger.addHandler(error_handler)
        error_logger.propagate = False
        app.error_logger = error_logger
        
        print(f"✅ Backend logging initialized in: {ANALYTICS_DIR}")


def get_client_ip():
    """Get real client IP address considering proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr or 'Unknown'


def get_request_id():
    """Generate unique request ID for tracking"""
    data = f"{datetime.now().timestamp()}{get_client_ip()}{request.path}"
    return hashlib.md5(data.encode()).hexdigest()[:8]


def write_to_backend_log(log_file, data):
    """Direct write to backend log file (fallback method)"""
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_line = f"{timestamp} | INFO | {json.dumps(data)}\n"
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(log_line)
            f.flush()
        return True
    except Exception as e:
        print(f"Error writing to backend log: {e}")
        return False


def log_security_event(app, request_type='ACCESS', status=200, details=None):
    """Log security event with all relevant details to backend logs"""
    try:
        ip = get_client_ip()
        method = request.method
        path = request.path
        user_agent = request.headers.get('User-Agent', 'Unknown')
        user = session.get('username', 'Anonymous')
        request_id = getattr(g, 'request_id', get_request_id())
        g.request_id = request_id
        
        # Calculate duration if available
        duration_ms = 0
        if hasattr(g, 'start_time'):
            duration_ms = (datetime.now() - g.start_time).total_seconds() * 1000
        
        log_data = {
            'request_id': request_id,
            'ip': ip,
            'user': user,
            'method': method,
            'path': path,
            'status': status,
            'type': request_type,
            'user_agent': user_agent[:200],
            'duration_ms': round(duration_ms, 2)
        }
        
        referrer = request.headers.get('Referer', '')
        if referrer:
            log_data['referrer'] = referrer[:200]
        
        if details:
            log_data['details'] = details
        
        # Write to backend access log for all requests
        if hasattr(app, 'access_logger'):
            app.access_logger.info(json.dumps(log_data))
        else:
            # Fallback direct write
            write_to_backend_log(BACKEND_ACCESS_LOG, log_data)
        
        # Write to auth log for authentication events
        if request_type == 'AUTH' or '/login' in path or '/logout' in path:
            if hasattr(app, 'auth_logger'):
                app.auth_logger.info(json.dumps(log_data))
            else:
                write_to_backend_log(BACKEND_AUTH_LOG, log_data)
        
        # Write to security log for POST/PUT/DELETE operations (content changes)
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            security_data = log_data.copy()
            security_data['event_type'] = 'content_change'
            if hasattr(app, 'security_logger'):
                app.security_logger.info(json.dumps(security_data))
            else:
                write_to_backend_log(BACKEND_SECURITY_LOG, security_data)
        
        # Write to error log for server errors
        if status >= 500 and hasattr(app, 'error_logger'):
            app.error_logger.error(json.dumps(log_data))
            
    except Exception as e:
        print(f"Error in log_security_event: {e}")
        if hasattr(app, 'error_logger'):
            app.error_logger.error(f"Error in log_security_event: {e}")


# =====================================================
# CREATE FLASK APP
# =====================================================

app = Flask(__name__,
            template_folder=str(BACKEND_DIR / 'templates'),
            static_folder=str(BACKEND_DIR / 'static'))
app.secret_key = SECRET_KEY

# Initialize security logging with new analytics directory
SecurityLogger(app)

# Initialize database
ensure_db_and_migrations()

# =====================================================
# REQUEST LOGGING MIDDLEWARE
# =====================================================

@app.before_request
def before_request():
    """Log request before processing"""
    g.start_time = datetime.now()
    g.request_id = get_request_id()
    
    # Log suspicious patterns
    if any(pattern in request.path.lower() for pattern in ['.php', '.asp', 'wp-', 'adminer', 'phpmyadmin']):
        log_security_event(
            app,
            request_type='SUSPICIOUS',
            status=0,
            details={'reason': 'Suspicious path pattern detected'}
        )
    
    # Log file access attempts
    if '.' in request.path and not request.path.endswith(('.html', '.css', '.js', '.jpg', '.png', '.gif', '.ico')):
        log_security_event(
            app,
            request_type='FILE_ACCESS',
            status=0,
            details={'file': request.path}
        )


@app.after_request
def after_request(response):
    """Log request after processing"""
    try:
        if hasattr(g, 'start_time'):
            duration = (datetime.now() - g.start_time).total_seconds() * 1000
        else:
            duration = 0
        
        request_type = 'ACCESS'
        if '/auth/' in request.path or '/login' in request.path:
            request_type = 'AUTH'
        elif '/admin/' in request.path:
            request_type = 'ADMIN'
        elif '/api/' in request.path:
            request_type = 'API'
        
        log_security_event(
            app,
            request_type=request_type,
            status=response.status_code,
            details={'duration_ms': round(duration, 2)}
        )
        
        # Add security headers
        response.headers['X-Request-ID'] = getattr(g, 'request_id', '')
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Server'] = 'CPP-Backend'
        
    except Exception as e:
        app.logger.error(f"Error in after_request: {e}")
    
    return response


# =====================================================
# STATIC FILE SERVING
# =====================================================

@app.route('/UI/<path:filename>')
def serve_ui(filename):
    """Serve files from the UI folder."""
    ui_path = ROOT_DIR / 'UI'
    if '..' in filename or (ui_path / filename).is_dir():
        abort(404)
    return send_from_directory(ui_path, filename)


@app.route('/assets/<path:filename>')
def serve_assets(filename):
    """Serve files from the assets folder."""
    assets_path = ROOT_DIR / 'assets'
    if '..' in filename or (assets_path / filename).is_dir():
        abort(404)
    return send_from_directory(assets_path, filename)


@app.route('/pages/<path:filename>')
def serve_pages(filename):
    """Serve files from the pages folder."""
    pages_path = ROOT_DIR / 'pages'
    if '..' in filename or (pages_path / filename).is_dir():
        abort(404)
    return send_from_directory(pages_path, filename)


@app.route('/favicon.ico')
def favicon():
    """Handle favicon requests."""
    fav = ROOT_DIR / 'favicon.ico'
    if fav.exists():
        return send_from_directory(ROOT_DIR, 'favicon.ico')
    return '', 204


@app.route('/<path:filename>')
def serve_root_file(filename):
    """Serve other root files."""
    # Skip API and admin paths
    if filename.startswith('cppipr_cms') or filename.startswith('api'):
        abort(404)
    
    root_file = ROOT_DIR / filename
    if root_file.exists() and root_file.is_file():
        return send_from_directory(ROOT_DIR, filename)
    abort(404)


# =====================================================
# ERROR HANDLING
# =====================================================

@app.errorhandler(403)
def forbidden_error(error):
    log_security_event(
        app,
        request_type='ACCESS_DENIED',
        status=403,
        details={'reason': str(error)}
    )
    from routes.error import render_error_template
    return render_error_template(403, "Access Denied", "You don't have permission to access this resource."), 403


@app.errorhandler(404)
def not_found_error(error):
    log_security_event(
        app,
        request_type='NOT_FOUND',
        status=404,
        details={'path': request.path}
    )
    from routes.error import render_error_template
    return render_error_template(404, "Page Not Found", "The page you are looking for doesn't exist."), 404


@app.errorhandler(500)
def internal_error(error):
    log_security_event(
        app,
        request_type='ERROR',
        status=500,
        details={'error': str(error)}
    )
    from routes.error import render_error_template
    return render_error_template(500, "Internal Server Error", "Something went wrong on our end."), 500


# =====================================================
# BLUEPRINT REGISTRATION
# =====================================================

app.register_blueprint(admin_auth)
app.register_blueprint(admin_home_bp)
app.register_blueprint(admin_carousal_bp)
app.register_blueprint(admin_notice)
app.register_blueprint(admin_research)
app.register_blueprint(admin_publication)
app.register_blueprint(admin_forms_links_bp)
app.register_blueprint(admin_people_bp)
app.register_blueprint(admin_tender_bp)
app.register_blueprint(admin_advertisement_bp)
app.register_blueprint(public_api)
app.register_blueprint(admin_analytics)  # Analytics blueprint

# Register error handlers
app = register_error_handlers(app)


# =====================================================
# ROOT REDIRECT
# =====================================================

@app.route('/')
def index():
    return redirect(url_for('admin_auth.admin_login'))


@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy', 
        'mode': 'backend',
        'analytics_dir': str(ANALYTICS_DIR),
        'log_files': {
            'access': str(BACKEND_ACCESS_LOG),
            'auth': str(BACKEND_AUTH_LOG),
            'security': str(BACKEND_SECURITY_LOG),
            'error': str(BACKEND_ERROR_LOG)
        }
    })


@app.route('/analytics-status')
def analytics_status():
    """Check analytics logging status"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    status = {
        'analytics_dir_exists': ANALYTICS_DIR.exists(),
        'analytics_dir_path': str(ANALYTICS_DIR),
        'log_files': {}
    }
    
    for log_file in [BACKEND_ACCESS_LOG, BACKEND_AUTH_LOG, BACKEND_SECURITY_LOG, BACKEND_ERROR_LOG]:
        if log_file.exists():
            size = log_file.stat().st_size
            status['log_files'][log_file.name] = {
                'exists': True,
                'size_bytes': size,
                'size_kb': round(size / 1024, 2)
            }
        else:
            status['log_files'][log_file.name] = {'exists': False, 'size_bytes': 0}
    
    return jsonify(status)


# =====================================================
# UTILITY FUNCTIONS
# =====================================================

def log_auth_event(event_type, username, success=True, details=None):
    """Helper function for logging authentication events from other modules"""
    try:
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'event': event_type,
            'username': username,
            'success': success,
            'ip': get_client_ip(),
            'user_agent': request.headers.get('User-Agent', 'Unknown') if request else 'Unknown'
        }
        
        if details:
            log_data['details'] = details
        
        if hasattr(app, 'auth_logger'):
            app.auth_logger.info(json.dumps(log_data))
        else:
            write_to_backend_log(BACKEND_AUTH_LOG, log_data)
    except Exception as e:
        app.logger.error(f"Error in log_auth_event: {e}")


# =====================================================
# RUN SERVER
# =====================================================

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5001)
    parser.add_argument('--host', default='0.0.0.0')
    args = parser.parse_args()

    print("="*60)
    print("CPP Website Backend Admin Server")
    print("="*60)
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    print(f"Analytics Directory: {ANALYTICS_DIR}")
    print(f"  - Backend Access Log: {BACKEND_ACCESS_LOG.name}")
    print(f"  - Backend Auth Log: {BACKEND_AUTH_LOG.name}")
    print(f"  - Backend Security Log: {BACKEND_SECURITY_LOG.name}")
    print(f"  - Backend Error Log: {BACKEND_ERROR_LOG.name}")
    print(f"Admin URL: http://{args.host}:{args.port}/cppipr_cms/login")
    print(f"Analytics URL: http://{args.host}:{args.port}/cppipr_cms/analytics")
    print(f"Analytics Status: http://{args.host}:{args.port}/analytics-status")
    print("="*60)

    app.run(host=args.host, port=args.port, debug=False)