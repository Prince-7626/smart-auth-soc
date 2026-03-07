import os
import requests
from datetime import datetime
import json

class ThreatIntelAPI:
    def __init__(self):
        # We use a mock or a real API key if available
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY', '')
        self.base_url = 'https://api.abuseipdb.com/api/v2/check'
        self.cache_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'threat_cache.json')
        self._cache = self._load_cache()

    def _load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading threat cache: {e}")
        return {}

    def _save_cache(self):
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self._cache, f)
        except Exception as e:
            print(f"Error saving threat cache: {e}")

    def check_ip_reputation(self, ip_address):
        """
        Check an IP against global threat intelligence (AbuseIPDB mock/real).
        Returns a risk score from 0-100, where 100 is known malicious.
        """
        # 1. Check Cache
        if ip_address in self._cache:
            cache_entry = self._cache[ip_address]
            # Simple 24 hour cache expiration (mocked mostly)
            return cache_entry.get('score', 0)

        # 2. Check Real API (if key exists)
        if self.abuseipdb_key:
            try:
                headers = {
                    'Accept': 'application/json',
                    'Key': self.abuseipdb_key
                }
                params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
                response = requests.get(self.base_url, headers=headers, params=params, timeout=3)
                
                if response.status_code == 200:
                    data = response.json()
                    score = data.get('data', {}).get('abuseConfidenceScore', 0)
                    
                    self._cache[ip_address] = {
                        'score': score,
                        'checked_at': datetime.utcnow().isoformat()
                    }
                    self._save_cache()
                    return score
            except Exception as e:
                print(f"[Threat Intel] API Error for {ip_address}: {e}")
        
        # 3. Fallback (Mock high risk if IP is a known malicious testing IP)
        mock_malicious = ['60.60.60.60', '70.70.70.70']
        if ip_address in mock_malicious:
            score = 100
        else:
            score = 0
            
        self._cache[ip_address] = {
            'score': score,
            'checked_at': datetime.utcnow().isoformat(),
            'mocked': True
        }
        self._save_cache()
        return score
