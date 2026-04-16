import urllib.request
import json
from datetime import datetime, timedelta
from Service_Provider.models import AttackLog, BlockedIP
from django.core.mail import send_mail
from django.conf import settings

# Memory-based tracking (resets on server restart)
login_attempts = {}
request_count = {}

def block_ip(ip):
    """Permanently block an IP address."""
    if ip != '127.0.0.1':
        BlockedIP.objects.get_or_create(ip_address=ip)

def get_ip_location(ip):
    if ip == '127.0.0.1':
        return "Localhost", "Localhost"
    try:
        url = f"http://ip-api.com/json/{ip}"
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                return data.get('country', 'Unknown'), data.get('city', 'Unknown')
    except Exception:
        pass
    return "Unknown", "Unknown"

def log_attack(ip, action, attack_type, status, is_alert=False, request=None):
    country, city = get_ip_location(ip)
    
    AttackLog.objects.create(
        ip_address=ip,
        action=action,
        attack_type=attack_type,
        status=status,
        is_alert=is_alert,
        country=country,
        city=city
    )
    
    if status == 'Blocked':
        block_ip(ip)

    if is_alert:
        # Django Message Alert (Global Session Popup)
        if request:
            from django.contrib import messages
            messages.error(request, f"🚨 SECURITY ALERT: {attack_type} detected from IP: {ip} ({city}, {country})")

        subject = f"🚨 AI Security Alert: {attack_type} Detected"
        msg = f"""
AI Cyber Portal Security Alert
------------------------------
Attack Type: {attack_type}
IP Address: {ip}
Location: {city}, {country}
Action Take: {action}
Status: {status}
Timestamp: {datetime.now()}
------------------------------
Please check the Security Logs for details.
"""
        try:
            # Use getattr to avoid crash if settings are missing
            admin_email = getattr(settings, 'ADMIN_EMAIL', 'admin@example.com')
            send_mail(subject, msg, settings.DEFAULT_FROM_EMAIL, [admin_email], fail_silently=True)
        except Exception:
            pass

def check_active_block(ip):
    """Check if the IP has a system-level block in the last 10 minutes."""
    ten_minutes_ago = datetime.now() - timedelta(minutes=10)
    return AttackLog.objects.filter(
        ip_address=ip, 
        action="Automatic Block: Multiple Login Failures",
        status='Blocked', 
        timestamp__gte=ten_minutes_ago
    ).exists()


def check_bruteforce(ip, request=None):
    # 1. Check if there is already an active persistent block
    if check_active_block(ip):
        return True

    now = datetime.now()

    if ip not in login_attempts:
        login_attempts[ip] = []

    login_attempts[ip].append(now)

    # 2. Check for new block (more than 5 attempts in 10 seconds)
    login_attempts[ip] = [
        t for t in login_attempts[ip] if now - t < timedelta(seconds=10)
    ]

    if len(login_attempts[ip]) > 5:
        # Create a new persistent block with alert
        log_attack(ip, "Automatic Block: Multiple Login Failures", "Brute Force", "Blocked", is_alert=True, request=request)
        return True

    return False

def detect_ddos(ip, request=None):
    now = datetime.now()

    if ip not in request_count:
        request_count[ip] = []

    request_count[ip].append(now)

    # Keep only requests from the last 5 seconds
    request_count[ip] = [
        t for t in request_count[ip] if now - t < timedelta(seconds=5)
    ]

    if len(request_count[ip]) > 20:
        log_attack(ip, "Too many requests", "DDoS", "Blocked", request=request)
        return True

    return False
