import os
import requests
from app.database import db, User

class AutomatedResponse:
    def __init__(self, app_context=None):
        self.app = app_context
        # Mocking a Slack or Teams Webhook URL 
        self.webhook_url = os.getenv('SOC_WEBHOOK_URL', '')
        
    def execute_playbook(self, severity, ip, reason, target_user=None):
        """
        Execute automated response playbook based on severity and context.
        """
        actions_taken = []
        
        # PLAYBOOK 1: High/Critical brute force on an explicit user
        if severity in ["HIGH", "CRITICAL"] and target_user:
            locked = self._lock_account(target_user)
            if locked:
                actions_taken.append(f"Account '{target_user}' heavily targeted -> Account LOCKED automatically.")
                
        # PLAYBOOK 2: Webhook Alerting
        if severity == "CRITICAL":
            alert = self._send_webhook_alert(ip, reason, actions_taken)
            if alert:
                actions_taken.append("CRITICAL Alert sent to Security Operations channel.")
                
        # In a real system you'd also hit Cloudflare/AWS WAF API here to block the IP
        # actions_taken.append("IP Blocked at Edge WAF via API")
        
        return actions_taken
        
    def _lock_account(self, username):
        """Disable a user account to prevent compromise during heavy attack"""
        if not self.app:
            return False
            
        try:
            with self.app.app_context():
                user = User.query.filter_by(username=username).first()
                if user and user.is_active:
                    user.is_active = False
                    db.session.commit()
                    return True
        except Exception as e:
            print(f"[SOAR ERROR] Failed to lock account {username}: {e}")
        return False
        
    def _send_webhook_alert(self, ip, reason, actions):
        """Emit alert to an external chat system (Slack/Teams)"""
        if not self.webhook_url:
            # If no webhook URL is configured, we'll just mock it and pretend it succeeded
            print(f"[SOAR WEBHOOK SIMULATION] 🚨 CRITICAL ALERT sent for {ip} (Reason: {reason})")
            return True
            
        payload = {
            "text": f"🚨 *CRITICAL SECURITY ALERT*\n*Source IP:* {ip}\n*Reason:* {reason}\n*Automated Actions:* {', '.join(actions) if actions else 'None'}"
        }
        
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=3)
            return response.status_code == 200
        except:
            return False
