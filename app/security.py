"""
Enhanced security features for SMART AUTH SOC
Includes CSRF protection, rate limiting, input validation, and API authentication
"""

from flask import request, jsonify
from functools import wraps
from datetime import datetime, timedelta
import hmac
import hashlib
import secrets
import re
from app.database import db, AuditLog

class RateLimiter:
    """Advanced rate limiting with sliding window"""
    
    def __init__(self):
        self.requests = {}  # {key: [(timestamp, 1), ...]}
    
    def is_allowed(self, identifier, max_requests=100, window_seconds=60):
        """Check if request is allowed within rate limit"""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)
        
        if identifier not in self.requests:
            self.requests[identifier] = []
        
        # Remove old requests outside window
        self.requests[identifier] = [
            (ts, count) for ts, count in self.requests[identifier]
            if ts > cutoff
        ]
        
        # Count current requests
        current_count = sum(count for _, count in self.requests[identifier])
        
        if current_count >= max_requests:
            return False
        
        # Add current request
        self.requests[identifier].append((now, 1))
        return True
    
    def get_remaining(self, identifier, max_requests=100, window_seconds=60):
        """Get remaining requests in current window"""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)
        
        if identifier not in self.requests:
            return max_requests
        
        current_count = sum(
            count for ts, count in self.requests[identifier]
            if ts > cutoff
        )
        return max(0, max_requests - current_count)


class InputValidator:
    """Input validation and sanitization"""
    
    @staticmethod
    def sanitize_string(value, max_length=255):
        """Sanitize string input"""
        if not isinstance(value, str):
            raise ValueError("Input must be string")
        
        if len(value) > max_length:
            raise ValueError(f"Input exceeds maximum length of {max_length}")
        
        # Remove potential XSS vectors
        dangerous_chars = ['<', '>', '"', "'", ';', '--']
        for char in dangerous_chars:
            value = value.replace(char, '')
        
        return value.strip()
    
    @staticmethod
    def validate_ip_address(ip_str):
        """Validate IPv4 and IPv6 addresses"""
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # IPv6 pattern (simplified)
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        
        if re.match(ipv4_pattern, ip_str):
            parts = ip_str.split('.')
            return all(0 <= int(p) <= 255 for p in parts)
        elif re.match(ipv6_pattern, ip_str):
            return True
        return False
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_username(username):
        """Validate username format"""
        # Alphanumeric, underscore, dash only, 3-32 chars
        pattern = r'^[a-zA-Z0-9_-]{3,32}$'
        return bool(re.match(pattern, username))
    
    @staticmethod
    def validate_password(password):
        """Validate password strength
        
        Requirements:
        - Minimum 8 characters
        - At least 1 uppercase letter
        - At least 1 lowercase letter
        - At least 1 number
        - At least 1 special character
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least 1 uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least 1 lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least 1 number"
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password):
            return False, "Password must contain at least 1 special character"
        
        return True, "Password strength is adequate"


class CSRFProtection:
    """CSRF token generation and validation"""
    
    @staticmethod
    def generate_token():
        """Generate a CSRF token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_token(token1, token2):
        """Safely compare tokens"""
        return hmac.compare_digest(token1, token2)


class APIAuth:
    """API Key and Token authentication for API endpoints"""
    
    @staticmethod
    def generate_api_key():
        """Generate a new API key for user/app"""
        return secrets.token_urlsafe(40)
    
    @staticmethod
    def generate_jwt_like_token(user_id, expires_in_hours=24):
        """Generate a simple token (JWT alternative for lightweight impl)"""
        import json
        import base64
        from datetime import datetime, timedelta
        
        payload = {
            'user_id': user_id,
            'iat': datetime.utcnow().isoformat(),
            'exp': (datetime.utcnow() + timedelta(hours=expires_in_hours)).isoformat()
        }
        
        # Sign payload
        payload_str = json.dumps(payload)
        signature = hmac.new(
            b'secret-signing-key',
            payload_str.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{base64.b64encode(payload_str.encode()).decode()}.{signature}"
    
    @staticmethod
    def verify_token(token):
        """Verify token validity"""
        try:
            import json
            import base64
            from datetime import datetime
            
            payload_b64, signature = token.split('.')
            payload_str = base64.b64decode(payload_b64).decode()
            payload = json.loads(payload_str)
            
            # Verify signature
            expected_sig = hmac.new(
                b'secret-signing-key',
                payload_str.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_sig):
                return None, "Invalid signature"
            
            # Verify expiration
            exp_time = datetime.fromisoformat(payload['exp'])
            if datetime.utcnow() > exp_time:
                return None, "Token expired"
            
            return payload['user_id'], "Valid"
        except Exception as e:
            return None, f"Token verification error: {str(e)}"


class SecurityHeaders:
    """Security headers for HTTP responses"""
    
    @staticmethod
    def apply_headers(response):
        """Apply all security headers to response"""
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Clickjacking protection
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        
        # XSS protection (for older browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Permission policy
        response.headers['Permissions-Policy'] = 'geolocation=()'
        
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' cdn.jsdelivr.net; "
            "connect-src 'self' api.geoip.com; "
        )
        
        # HSTS (only on HTTPS)
        if request.scheme == 'https':
            response.headers['Strict-Transport-Security'] = (
                'max-age=31536000; includeSubDomains; preload'
            )
        
        return response


class TwoFactorAuth:
    """Two-Factor Authentication support (TOTP)"""
    
    @staticmethod
    def generate_secret():
        """Generate base32 secret for 2FA"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def generate_backup_codes(count=10):
        """Generate backup codes for account recovery"""
        return [secrets.token_hex(4).upper() for _ in range(count)]


def require_api_key(f):
    """Decorator to require API key for endpoint"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        # Validate API key from database
        # In production, implement proper API key management
        # For now, accept any non-empty key
        if len(api_key) < 32:
            return jsonify({'error': 'Invalid API key'}), 401
        
        return f(*args, **kwargs)
    
    return decorated


def rate_limit(max_requests=100, window_seconds=60):
    """Decorator to rate limit endpoints"""
    limiter = RateLimiter()
    
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            identifier = request.remote_addr
            
            if not limiter.is_allowed(identifier, max_requests, window_seconds):
                remaining = limiter.get_remaining(identifier, max_requests, window_seconds)
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'remaining': remaining,
                    'reset_seconds': window_seconds
                }), 429
            
            return f(*args, **kwargs)
        
        return decorated
    
    return decorator
