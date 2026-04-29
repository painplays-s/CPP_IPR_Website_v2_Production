#!/usr/bin/env python3
"""
Frontend Server – Public Website (Production)
Serves static files and provides all public API endpoints.
Uses Waitress WSGI server - production ready, no warnings.
"""

import sys
from pathlib import Path

# Add backend directory to path so we can import its modules
BACKEND_DIR = Path(__file__).parent / 'backend'
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(BACKEND_DIR))

from flask import Flask, jsonify, request, g
from datetime import datetime
import json
import uuid
import logging
from logging.handlers import RotatingFileHandler
from waitress import serve

from config import SECRET_KEY
from routes.public_api import public_api
from routes.static_routes import static_routes
from routes.error import register_error_handlers

# ------------------------------------------------------------
# Suppress all Waitress queue warnings
# ------------------------------------------------------------
logging.getLogger('waitress').setLevel(logging.ERROR)
logging.getLogger('waitress.queue').setLevel(logging.ERROR)

# ------------------------------------------------------------
# Create Flask app
# ------------------------------------------------------------
app = Flask(__name__,
            template_folder=str(BACKEND_DIR / 'templates'),
            static_folder=str(PROJECT_ROOT))
app.secret_key = SECRET_KEY

# ------------------------------------------------------------
# Setup Analytics Directory and Logging for Frontend
# ------------------------------------------------------------

# Create analytics directory in root
ANALYTICS_DIR = Path(__file__).parent / 'analytics'
ANALYTICS_DIR.mkdir(exist_ok=True)

# Frontend log files
FRONTEND_ACCESS_LOG = ANALYTICS_DIR / 'frontend_access.log'
FRONTEND_ERRORS_LOG = ANALYTICS_DIR / 'frontend_errors.log'

# Create log files if they don't exist
for log_file in [FRONTEND_ACCESS_LOG, FRONTEND_ERRORS_LOG]:
    if not log_file.exists():
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(f"# Frontend log file created on {datetime.now().isoformat()}\n")

def get_client_ip():
    """Get real client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr or 'Unknown'

def write_frontend_log(log_file, data):
    """Write to frontend log file"""
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_line = f"{timestamp} | INFO | {json.dumps(data)}\n"
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(log_line)
            f.flush()
        return True
    except Exception as e:
        print(f"Error writing to frontend log: {e}")
        return False

# ------------------------------------------------------------
# Frontend Request Logging Middleware
# ------------------------------------------------------------

@app.before_request
def before_frontend_request():
    """Store request start time"""
    g.start_time = datetime.now()
    g.request_id = str(uuid.uuid4())[:8]

@app.after_request
def after_frontend_request(response):
    """Log all frontend requests"""
    # Skip logging for health checks and static assets
    if request.path == '/health' or request.path.startswith('/favicon.ico'):
        return response
    
    # Calculate duration
    duration_ms = 0
    if hasattr(g, 'start_time'):
        duration_ms = (datetime.now() - g.start_time).total_seconds() * 1000
    
    # Create log entry
    log_entry = {
        'request_id': getattr(g, 'request_id', 'unknown'),
        'ip': get_client_ip(),
        'method': request.method,
        'path': request.path,
        'status': response.status_code,
        'duration_ms': round(duration_ms, 2),
        'user_agent': request.headers.get('User-Agent', 'unknown')[:200],
        'referrer': request.headers.get('Referer', '')[:200]
    }
    
    # Write to frontend access log
    write_frontend_log(FRONTEND_ACCESS_LOG, log_entry)
    
    # Write to error log if status >= 400
    if response.status_code >= 400:
        write_frontend_log(FRONTEND_ERRORS_LOG, log_entry)
    
    # IMPORTANT: Don't add restrictive headers for PDFs
    # Let static_routes handle the headers properly
    if not request.path.lower().endswith('.pdf'):
        response.headers['X-Request-ID'] = getattr(g, 'request_id', '')
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Don't set X-Frame-Options for PDFs
    
    return response

# ------------------------------------------------------------
# Register Blueprints - THIS IS KEY
# ------------------------------------------------------------
app.register_blueprint(public_api)      # all /api/... endpoints
app.register_blueprint(static_routes)   # serves /pages, /assets, /UI, /, /favicon.ico - THIS HANDLES PDFs

# Register error handlers from backend
app = register_error_handlers(app)

# ------------------------------------------------------------
# Health check
# ------------------------------------------------------------
@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'mode': 'production',
        'server': 'waitress',
        'timestamp': datetime.now().isoformat(),
        'analytics_dir': str(ANALYTICS_DIR)
    })

# ------------------------------------------------------------
# Debug endpoint to check PDF files
# ------------------------------------------------------------
@app.route('/debug/pdf-list')
def debug_pdf_list():
    """List all PDF files for debugging"""
    tenders_path = PROJECT_ROOT / 'assets' / 'files' / 'tenders'
    notices_path = PROJECT_ROOT / 'assets' / 'files' / 'currentNotice'
    
    result = {}
    
    if tenders_path.exists():
        pdf_files = []
        for file in tenders_path.glob('*.pdf'):
            pdf_files.append({
                'name': file.name,
                'size': file.stat().st_size,
                'size_kb': round(file.stat().st_size / 1024, 2),
                'modified': datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
            })
        result['tenders'] = {
            'directory': str(tenders_path),
            'exists': tenders_path.exists(),
            'pdf_count': len(pdf_files),
            'pdf_files': pdf_files
        }
    
    if notices_path.exists():
        pdf_files = []
        for file in notices_path.glob('*.pdf'):
            pdf_files.append({
                'name': file.name,
                'size': file.stat().st_size,
                'size_kb': round(file.stat().st_size / 1024, 2),
                'modified': datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
            })
        result['notices'] = {
            'directory': str(notices_path),
            'exists': notices_path.exists(),
            'pdf_count': len(pdf_files),
            'pdf_files': pdf_files
        }
    
    return jsonify(result)

# ------------------------------------------------------------
# Run server with Waitress (Production WSGI Server)
# ------------------------------------------------------------
if __name__ == '__main__':
    import argparse
    
    # Suppress ALL Flask and Werkzeug warnings
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    logging.getLogger('flask').setLevel(logging.ERROR)
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--threads', type=int, default=8)  # Increased threads
    parser.add_argument('--connection-limit', type=int, default=2000)  # Increased limit
    args = parser.parse_args()

    print("="*60)
    print("CPP Website Frontend Server (PRODUCTION)")
    print("="*60)
    print(f"Server: Waitress WSGI Server")
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    print(f"Threads: {args.threads}")
    print(f"Connection Limit: {args.connection_limit}")
    print(f"Analytics Directory: {ANALYTICS_DIR}")
    print(f"Frontend Access Log: {FRONTEND_ACCESS_LOG}")
    print("="*60)
    print(f"Access URLs:")
    print(f"  Local: http://127.0.0.1:{args.port}")
    print(f"  Network: http://{args.host}:{args.port}")
    print("="*60)
    print("Starting Waitress server...")
    print("Press Ctrl+C to stop")
    print("="*60)
    
    # Serve with Waitress - Production grade WSGI server
    # Added asyncore loop to handle queue warnings
    serve(
        app,
        host=args.host,
        port=args.port,
        threads=args.threads,
        connection_limit=args.connection_limit,
        channel_timeout=300,  # 5 minutes timeout
        clear_untrusted_proxy_headers=False,
        ident=f'CPP-Frontend/{args.port}',
        asyncore_loop_timeout=1,  # Reduce queue buildup
        url_scheme='http'
    )