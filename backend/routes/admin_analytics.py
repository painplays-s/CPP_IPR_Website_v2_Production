from flask import Blueprint, render_template, session, flash, redirect, url_for, request, jsonify, make_response
import os
import json
import csv
import io
import traceback
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
import re

# Configure logging - keep basic logs but reduce analytics noise
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

admin_analytics = Blueprint('admin_analytics', __name__, url_prefix='/cppipr_cms')

# =====================================================
# HELPER FUNCTIONS
# =====================================================

def get_analytics_dir():
    """Get analytics directory path from root"""
    return Path(__file__).parent.parent.parent / 'analytics'

def parse_log_line(line):
    """Parse a single log line from log files"""
    try:
        if line.startswith('#') or not line.strip():
            return None
        parts = line.split(' | ', 2)
        if len(parts) >= 3:
            timestamp_str = parts[0]
            json_str = parts[2]
            data = json.loads(json_str)
            data['timestamp'] = timestamp_str
            return data
    except Exception:
        pass
    return None

def read_logs(log_file_name, days=365):
    """Read and parse log files from analytics directory"""
    logs = []
    cutoff_date = datetime.now() - timedelta(days=days)
    
    analytics_dir = get_analytics_dir()
    log_path = analytics_dir / log_file_name
    
    if not log_path.exists():
        return logs
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed and 'timestamp' in parsed:
                    try:
                        log_date = datetime.strptime(parsed['timestamp'], '%Y-%m-%d %H:%M:%S')
                        if log_date >= cutoff_date:
                            logs.append(parsed)
                    except:
                        logs.append(parsed)
    except Exception as e:
        pass
    
    return logs

def get_frontend_logs(days=30):
    """Get frontend logs from frontend_access.log"""
    all_logs = read_logs('frontend_access.log', days=days)
    frontend_logs = []
    
    for log in all_logs:
        path = log.get('path', '')
        # Include only frontend page views (not assets)
        if path == '/' or path.startswith('/pages/') or path.startswith('/UI/') or path.startswith('/assets/'):
            if not path.endswith(('.css', '.js', '.jpg', '.png', '.gif', '.ico', '.woff', '.woff2')):
                frontend_logs.append(log)
        # Include simple GET requests that look like page views
        elif log.get('method') == 'GET' and not path.startswith('/cppipr_cms') and not path.startswith('/health'):
            if not path.endswith(('.css', '.js', '.jpg', '.png', '.gif', '.ico')):
                frontend_logs.append(log)
    
    return frontend_logs

def get_backend_logs(days=30):
    """Get backend logs from backend_access.log"""
    return read_logs('backend_access.log', days=days)

def get_backend_auth_logs(days=30):
    """Get backend authentication logs"""
    auth_logs = read_logs('backend_auth.log', days=days)
    
    # Also check backend_access.log for login events if auth.log is empty
    if not auth_logs:
        access_logs = read_logs('backend_access.log', days=days)
        for log in access_logs:
            path = log.get('path', '')
            if '/login' in path or '/logout' in path:
                auth_logs.append({
                    'timestamp': log.get('timestamp'),
                    'user': log.get('user', 'Unknown'),
                    'event': 'login_attempt' if '/login' in path else 'logout',
                    'success': log.get('status') == 302 or log.get('status') == 200,
                    'ip': log.get('ip', 'unknown'),
                    'method': log.get('method')
                })
    
    return auth_logs

def get_backend_security_logs(days=30):
    """Get backend security logs"""
    return read_logs('backend_security.log', days=days)

def detect_admin_module(path, method):
    """Detect which admin module is being accessed"""
    if '/tender' in path:
        return 'Tender Management'
    elif '/carousel' in path or '/carousal' in path:
        return 'Carousel Management'
    elif '/notice' in path:
        return 'Notice Management'
    elif '/research' in path:
        return 'Research Management'
    elif '/publication' in path:
        return 'Publication Management'
    elif '/people' in path:
        return 'People Management'
    elif '/advertisement' in path:
        return 'Advertisement Management'
    elif '/forms-links' in path:
        return 'Forms & Links Management'
    elif '/dashboard' in path or '/home' in path:
        return 'Dashboard'
    elif '/login' in path:
        return 'Login'
    elif '/logout' in path:
        return 'Logout'
    elif '/analytics' in path:
        return 'Analytics'
    else:
        return 'General Admin'

# =====================================================
# ROUTES
# =====================================================

@admin_analytics.route('/analytics')
def admin_analytics_page():
    """Main analytics dashboard page"""
    try:
        if not session.get('admin_logged_in'):
            flash('Please login to access the admin panel.', 'error')
            return redirect(url_for('admin_auth.admin_login'))
        
        return render_template('admin_analytic.html')
    except Exception as e:
        logger.error(f"Error in admin_analytics_page: {str(e)}")
        flash(f'Error loading analytics page: {str(e)}', 'error')
        return redirect(url_for('admin_home.admin_home'))

@admin_analytics.route('/analytics/data')
def get_analytics_data():
    """API endpoint to get all analytics data"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        period = request.args.get('period', 'all')
        days_map = {'daily': 1, 'monthly': 30, 'yearly': 365, 'all': 3650}
        days = days_map.get(period, 365)
        
        # Get logs from both frontend and backend
        frontend_logs = get_frontend_logs(days)
        backend_logs = get_backend_logs(days)
        auth_logs = get_backend_auth_logs(days)
        security_logs = get_backend_security_logs(days)
        
        # Analyze data
        frontend_stats = analyze_frontend_traffic(frontend_logs)
        backend_stats = analyze_backend_activity(backend_logs, auth_logs, security_logs)
        seo_stats = analyze_seo_status(frontend_logs)
        
        response_data = {
            'frontend': frontend_stats,
            'backend': backend_stats,
            'seo': seo_stats,
            'period': period,
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error in get_analytics_data: {str(e)}")
        return jsonify({'error': str(e)}), 500

def analyze_frontend_traffic(logs):
    """Analyze frontend server traffic"""
    if not logs:
        return {
            'total_visitors': 0,
            'total_hits': 0,
            'hourly_distribution': {},
            'daily_trend': {},
            'top_pages': {},
            'visitor_ip_details': [],
            'page_visitor_details': [],
            'avg_hits_per_visitor': 0
        }
    
    unique_ips = set()
    hourly_visits = Counter()
    daily_visits = defaultdict(int)
    page_visits = Counter()
    ip_details = defaultdict(lambda: {'count': 0, 'pages': set(), 'last_seen': None, 'first_seen': None})
    
    for log in logs:
        ip = log.get('ip', 'unknown')
        # Clean up IP display
        if ip == '127.0.0.1' or ip == '::1':
            ip = 'Localhost'
        
        path = log.get('path', '/')
        if path == '/':
            path = 'Homepage'
        elif path.startswith('/pages/'):
            path = path.replace('/pages/', 'Page: ')
        elif path.startswith('/UI/'):
            path = 'UI Component'
        
        timestamp = log.get('timestamp')
        
        unique_ips.add(ip)
        page_visits[path] += 1
        
        # Track IP details
        ip_details[ip]['count'] += 1
        ip_details[ip]['pages'].add(path)
        if timestamp:
            if not ip_details[ip]['first_seen'] or timestamp < ip_details[ip]['first_seen']:
                ip_details[ip]['first_seen'] = timestamp
            if not ip_details[ip]['last_seen'] or timestamp > ip_details[ip]['last_seen']:
                ip_details[ip]['last_seen'] = timestamp
        
        # Time-based analysis
        try:
            dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            hour_key = f"{dt.hour:02d}:00"
            day_key = dt.strftime('%Y-%m-%d')
            hourly_visits[hour_key] += 1
            daily_visits[day_key] += 1
        except:
            pass
    
    # Prepare visitor IP details
    visitor_details = []
    for ip, details in sorted(ip_details.items(), key=lambda x: x[1]['count'], reverse=True)[:50]:
        visitor_details.append({
            'ip': ip,
            'visit_count': details['count'],
            'pages_visited': list(details['pages'])[:10],
            'first_seen': details['first_seen'],
            'last_seen': details['last_seen']
        })
    
    # Page visitor details
    page_details = []
    for page, count in page_visits.most_common(20):
        unique_page_visitors = set()
        for log in logs:
            log_path = log.get('path', '/')
            compare_path = 'Homepage' if log_path == '/' else log_path.replace('/pages/', 'Page: ')
            if compare_path == page:
                unique_page_visitors.add(log.get('ip', 'unknown'))
        
        page_details.append({
            'page': page,
            'total_visits': count,
            'unique_visitors': len(unique_page_visitors),
            'last_visit': next((log.get('timestamp') for log in reversed(logs) if (log.get('path') == '/' and page == 'Homepage') or log.get('path', '').replace('/pages/', 'Page: ') == page), None)
        })
    
    # Daily trend (last 30 days)
    daily_trend = dict(sorted(daily_visits.items())[-30:])
    
    return {
        'total_visitors': len(unique_ips),
        'total_hits': len(logs),
        'hourly_distribution': dict(hourly_visits),
        'daily_trend': daily_trend,
        'top_pages': dict(page_visits.most_common(10)),
        'visitor_ip_details': visitor_details,
        'page_visitor_details': page_details,
        'avg_hits_per_visitor': round(len(logs) / len(unique_ips), 2) if unique_ips else 0
    }

def analyze_backend_activity(backend_logs, auth_logs, security_logs):
    """Analyze admin panel activity"""
    
    admin_sessions = defaultdict(lambda: {
        'visits': 0,
        'pages': set(),
        'modules': defaultdict(int),
        'first_seen': None,
        'last_seen': None,
        'actions': []
    })
    
    for log in backend_logs:
        user = log.get('user', 'Anonymous')
        path = log.get('path', '')
        timestamp = log.get('timestamp')
        method = log.get('method', 'GET')
        
        if user != 'Anonymous':
            module = detect_admin_module(path, method)
            
            admin_sessions[user]['visits'] += 1
            admin_sessions[user]['pages'].add(path)
            admin_sessions[user]['modules'][module] += 1
            
            if timestamp:
                if not admin_sessions[user]['first_seen'] or timestamp < admin_sessions[user]['first_seen']:
                    admin_sessions[user]['first_seen'] = timestamp
                if not admin_sessions[user]['last_seen'] or timestamp > admin_sessions[user]['last_seen']:
                    admin_sessions[user]['last_seen'] = timestamp
            
            # Track content management actions
            if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                admin_sessions[user]['actions'].append({
                    'timestamp': timestamp,
                    'path': path,
                    'method': method,
                    'module': module
                })
    
    # Authentication events - IMPROVED PARSING
    auth_events = []
    seen_events = set()  # To avoid duplicates
    
    for log in auth_logs:
        timestamp = log.get('timestamp')
        username = log.get('user') or log.get('username') or log.get('user', 'Unknown')
        event = log.get('event', 'login')
        success = log.get('success', True)
        ip = log.get('ip', 'unknown')
        
        # Create a unique key to avoid duplicates
        event_key = f"{timestamp}_{username}_{event}"
        if event_key not in seen_events:
            seen_events.add(event_key)
            auth_events.append({
                'timestamp': timestamp,
                'username': username,
                'event': event,
                'success': success,
                'ip': ip
            })
    
    # Also check backend_logs for login/logout events
    for log in backend_logs:
        path = log.get('path', '')
        if '/login' in path or '/logout' in path:
            timestamp = log.get('timestamp')
            username = log.get('user', 'Unknown')
            event = 'login' if '/login' in path else 'logout'
            success = log.get('status') in [200, 302]
            ip = log.get('ip', 'unknown')
            
            event_key = f"{timestamp}_{username}_{event}"
            if event_key not in seen_events:
                seen_events.add(event_key)
                auth_events.append({
                    'timestamp': timestamp,
                    'username': username,
                    'event': event,
                    'success': success,
                    'ip': ip
                })
    
    # Sort by timestamp (newest first)
    auth_events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    # Content changes from security logs
    content_changes = []
    module_activity = defaultdict(list)
    
    for log in security_logs:
        method = log.get('method', '')
        path = log.get('path', '')
        user = log.get('user', 'Anonymous')
        timestamp = log.get('timestamp')
        
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            module = detect_admin_module(path, method)
            
            change_record = {
                'timestamp': timestamp,
                'user': user,
                'ip': log.get('ip'),
                'method': method,
                'path': path,
                'module': module,
                'details': f"{method} operation"
            }
            
            content_changes.append(change_record)
            module_activity[module].append(change_record)
    
    # Also check backend_logs for POST/PUT/DELETE operations
    for log in backend_logs:
        method = log.get('method', '')
        path = log.get('path', '')
        user = log.get('user', 'Anonymous')
        timestamp = log.get('timestamp')
        
        if method in ['POST', 'PUT', 'DELETE', 'PATCH'] and user != 'Anonymous':
            module = detect_admin_module(path, method)
            
            # Check if already in content_changes
            existing = any(
                c.get('timestamp') == timestamp and c.get('path') == path 
                for c in content_changes
            )
            
            if not existing:
                content_changes.append({
                    'timestamp': timestamp,
                    'user': user,
                    'ip': log.get('ip'),
                    'method': method,
                    'path': path,
                    'module': module,
                    'details': f"{method} operation performed"
                })
                
                if module not in module_activity:
                    module_activity[module] = []
                module_activity[module].append({
                    'timestamp': timestamp,
                    'user': user,
                    'method': method,
                    'details': f"{method} operation"
                })
    
    # Sort content changes by timestamp (newest first)
    content_changes.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    # Prepare user sessions
    user_sessions = {}
    for user, data in admin_sessions.items():
        user_sessions[user] = {
            'visits': data['visits'],
            'pages_visited': len(data['pages']),
            'modules_accessed': dict(data['modules']),
            'first_seen': data['first_seen'],
            'last_seen': data['last_seen'],
            'content_actions': len(data['actions'])
        }
    
    # Module summary
    module_summary = {}
    for module, changes in module_activity.items():
        module_summary[module] = {
            'total_changes': len(changes),
            'recent_changes': changes[:5]
        }
    
    return {
        'admin_sessions': user_sessions,
        'total_admin_visits': len(backend_logs),
        'unique_admin_users': len(admin_sessions),
        'auth_events': auth_events[:50],
        'content_changes': content_changes[:100],
        'module_activity': module_summary,
        'recent_auth_failures': [e for e in auth_events if not e.get('success', False)][:20]
    }

def analyze_seo_status(frontend_logs):
    """Analyze SEO status - simplified version"""
    
    # Mobile vs Desktop traffic
    mobile_agents = 0
    desktop_agents = 0
    
    for log in frontend_logs:
        user_agent = log.get('user_agent', '').lower()
        if 'mobile' in user_agent or 'android' in user_agent or 'iphone' in user_agent:
            mobile_agents += 1
        else:
            desktop_agents += 1
    
    total_agents = mobile_agents + desktop_agents
    mobile_percentage = (mobile_agents / total_agents * 100) if total_agents > 0 else 0
    desktop_percentage = (desktop_agents / total_agents * 100) if total_agents > 0 else 0
    
    # Page load speed
    response_times = [log.get('duration_ms', 0) for log in frontend_logs if log.get('duration_ms', 0) > 0]
    avg_load_time = sum(response_times) / len(response_times) if response_times else 500
    
    # 404 errors
    not_found_count = len([log for log in frontend_logs if log.get('status') == 404])
    not_found_percentage = (not_found_count / len(frontend_logs) * 100) if frontend_logs else 0
    
    # Pages indexed
    pages_visited = set()
    for log in frontend_logs:
        path = log.get('path', '/')
        if path == '/':
            pages_visited.add('Homepage')
        elif path.startswith('/pages/'):
            pages_visited.add(path.replace('/pages/', ''))
        else:
            pages_visited.add(path)
    
    return {
        'mobile_percentage': round(mobile_percentage, 1),
        'desktop_percentage': round(desktop_percentage, 1),
        'total_traffic': len(frontend_logs),
        'mobile_traffic': mobile_agents,
        'desktop_traffic': desktop_agents,
        'avg_load_time_ms': round(avg_load_time, 2),
        'not_found_percentage': round(not_found_percentage, 1),
        'total_pages_indexed': len(pages_visited),
        'pages_list': list(pages_visited)[:20]
    }

# =====================================================
# EXPORT FUNCTIONS
# =====================================================

@admin_analytics.route('/analytics/export-csv')
def export_analytics_csv():
    """Export analytics data as CSV"""
    if not session.get('admin_logged_in'):
        flash('Please login to access the admin panel.', 'error')
        return redirect(url_for('admin_auth.admin_login'))
    
    try:
        export_type = request.args.get('type', 'frontend')
        period = request.args.get('period', 'all')
        days_map = {'daily': 1, 'monthly': 30, 'yearly': 365, 'all': 3650}
        days = days_map.get(period, 365)
        
        output = io.StringIO()
        
        if export_type == 'frontend':
            logs = get_frontend_logs(days)
            writer = csv.writer(output)
            writer.writerow(['Timestamp', 'IP Address', 'Path', 'Method', 'Status', 'Duration (ms)', 'User Agent'])
            
            for log in logs:
                writer.writerow([
                    log.get('timestamp'),
                    log.get('ip'),
                    log.get('path'),
                    log.get('method'),
                    log.get('status'),
                    log.get('duration_ms', ''),
                    log.get('user_agent', '')[:100]
                ])
        
        elif export_type == 'backend':
            logs = get_backend_logs(days)
            writer = csv.writer(output)
            writer.writerow(['Timestamp', 'User', 'IP', 'Path', 'Method', 'Module', 'Status'])
            
            for log in logs:
                module = detect_admin_module(log.get('path', ''), log.get('method', 'GET'))
                writer.writerow([
                    log.get('timestamp'),
                    log.get('user', 'Anonymous'),
                    log.get('ip'),
                    log.get('path'),
                    log.get('method'),
                    module,
                    log.get('status')
                ])
        
        elif export_type == 'auth':
            logs = get_backend_auth_logs(days)
            writer = csv.writer(output)
            writer.writerow(['Timestamp', 'Username', 'Event', 'Success', 'IP'])
            
            for log in logs:
                writer.writerow([
                    log.get('timestamp'),
                    log.get('username') or log.get('user') or 'Unknown',
                    log.get('event') or 'login',
                    'Yes' if log.get('success', True) else 'No',
                    log.get('ip')
                ])
        
        else:  # seo
            frontend_logs = get_frontend_logs(days)
            seo_stats = analyze_seo_status(frontend_logs)
            writer = csv.writer(output)
            writer.writerow(['Metric', 'Value'])
            writer.writerow(['Total Traffic', seo_stats['total_traffic']])
            writer.writerow(['Mobile Traffic', f"{seo_stats['mobile_traffic']} ({seo_stats['mobile_percentage']}%)"])
            writer.writerow(['Desktop Traffic', f"{seo_stats['desktop_traffic']} ({seo_stats['desktop_percentage']}%)"])
            writer.writerow(['Average Load Time (ms)', seo_stats['avg_load_time_ms']])
            writer.writerow(['404 Error Rate %', seo_stats['not_found_percentage']])
            writer.writerow(['Pages Indexed', seo_stats['total_pages_indexed']])
            writer.writerow([])
            writer.writerow(['Pages Found'])
            for page in seo_stats['pages_list']:
                writer.writerow([page])
        
        output.seek(0)
        filename = f"analytics_{export_type}_{period}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        return response
        
    except Exception as e:
        logger.error(f"Error in export_analytics_csv: {str(e)}")
        flash(f'Error exporting data: {str(e)}', 'error')
        return redirect(url_for('admin_analytics.admin_analytics_page'))

@admin_analytics.route('/analytics/export-pdf')
def export_analytics_pdf():
    """Export complete analytics report as PDF"""
    if not session.get('admin_logged_in'):
        flash('Please login to access the admin panel.', 'error')
        return redirect(url_for('admin_auth.admin_login'))
    
    try:
        # Try to import reportlab
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter, landscape
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            flash('PDF export requires reportlab. Install with: pip install reportlab', 'error')
            return redirect(url_for('admin_analytics.admin_analytics_page'))
        
        period = request.args.get('period', 'all')
        days_map = {'daily': 1, 'monthly': 30, 'yearly': 365, 'all': 3650}
        days = days_map.get(period, 365)
        
        # Get data
        frontend_logs = get_frontend_logs(days)
        backend_logs = get_backend_logs(days)
        auth_logs = get_backend_auth_logs(days)
        
        frontend_stats = analyze_frontend_traffic(frontend_logs)
        backend_stats = analyze_backend_activity(backend_logs, auth_logs, [])
        seo_stats = analyze_seo_status(frontend_logs)
        
        # Create PDF
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
        styles = getSampleStyleSheet()
        elements = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=20,
            textColor=colors.HexColor('#1e3c72'),
            alignment=TA_CENTER,
            spaceAfter=20
        )
        elements.append(Paragraph("CPP Website Analytics Report", title_style))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Paragraph(f"Period: {period.capitalize()}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Frontend Section
        elements.append(Paragraph("A. Frontend Traffic Analysis", styles['Heading2']))
        elements.append(Spacer(1, 10))
        
        frontend_data = [
            ['Metric', 'Value'],
            ['Total Unique Visitors', str(frontend_stats['total_visitors'])],
            ['Total Hits', str(frontend_stats['total_hits'])],
            ['Average Hits per Visitor', str(frontend_stats['avg_hits_per_visitor'])],
        ]
        
        frontend_table = Table(frontend_data, colWidths=[200, 200])
        frontend_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(frontend_table)
        elements.append(Spacer(1, 20))
        
        # Top Pages
        if frontend_stats['top_pages']:
            elements.append(Paragraph("Top 10 Most Visited Pages", styles['Heading3']))
            top_pages_data = [['Page', 'Visits']]
            for page, count in list(frontend_stats['top_pages'].items())[:10]:
                top_pages_data.append([page[:50], str(count)])
            
            pages_table = Table(top_pages_data, colWidths=[300, 100])
            pages_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(pages_table)
            elements.append(Spacer(1, 20))
        
        # Backend Section
        elements.append(PageBreak())
        elements.append(Paragraph("B. Admin Panel Activity", styles['Heading2']))
        elements.append(Spacer(1, 10))
        
        backend_data = [
            ['Metric', 'Value'],
            ['Total Admin Visits', str(backend_stats['total_admin_visits'])],
            ['Unique Admin Users', str(backend_stats['unique_admin_users'])],
            ['Total Content Changes', str(len(backend_stats['content_changes']))],
        ]
        
        backend_table = Table(backend_data, colWidths=[200, 200])
        backend_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(backend_table)
        elements.append(Spacer(1, 20))
        
        # Admin Sessions
        if backend_stats['admin_sessions']:
            elements.append(Paragraph("Admin User Sessions", styles['Heading3']))
            sessions_data = [['User', 'Visits', 'Pages Visited', 'Content Actions']]
            for user, data in list(backend_stats['admin_sessions'].items())[:10]:
                sessions_data.append([user, str(data['visits']), str(data['pages_visited']), str(data['content_actions'])])
            
            sessions_table = Table(sessions_data, colWidths=[100, 80, 100, 100])
            sessions_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(sessions_table)
            elements.append(Spacer(1, 20))
        
        # Authentication Events Section
        if backend_stats['auth_events']:
            elements.append(Paragraph("Recent Authentication Events", styles['Heading3']))
            auth_data = [['Time', 'User', 'Event', 'Status', 'IP']]
            for event in backend_stats['auth_events'][:20]:
                auth_data.append([
                    event.get('timestamp', 'N/A')[:16],
                    event.get('username', 'Unknown'),
                    event.get('event', 'login'),
                    'Success' if event.get('success', False) else 'Failed',
                    event.get('ip', 'unknown')
                ])
            
            auth_table = Table(auth_data, colWidths=[100, 80, 60, 60, 100])
            auth_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(auth_table)
            elements.append(Spacer(1, 20))
        
        # SEO Section
        elements.append(PageBreak())
        elements.append(Paragraph("C. SEO Status Report", styles['Heading2']))
        elements.append(Spacer(1, 10))
        
        seo_data = [
            ['Metric', 'Value'],
            ['Total Traffic', str(seo_stats['total_traffic'])],
            ['Mobile Traffic', f"{seo_stats['mobile_traffic']} ({seo_stats['mobile_percentage']}%)"],
            ['Desktop Traffic', f"{seo_stats['desktop_traffic']} ({seo_stats['desktop_percentage']}%)"],
            ['Average Load Time', f"{seo_stats['avg_load_time_ms']}ms"],
            ['404 Error Rate', f"{seo_stats['not_found_percentage']}%"],
            ['Pages Indexed', str(seo_stats['total_pages_indexed'])],
        ]
        
        seo_table = Table(seo_data, colWidths=[200, 200])
        seo_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(seo_table)
        
        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=analytics_report_{period}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        return response
        
    except Exception as e:
        logger.error(f"Error generating PDF: {str(e)}")
        flash(f'Error generating PDF: {str(e)}', 'error')
        return redirect(url_for('admin_analytics.admin_analytics_page'))