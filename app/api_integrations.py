"""
External API integrations for SMART AUTH SOC
Includes GeoIP, threat intelligence, and security feeds
"""

import requests
import os
from datetime import datetime, timedelta
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)

class GeoIPProvider:
    """GeoIP lookup using IP-API service"""
    
    BASE_URL = "http://ip-api.com/json/"
    CACHE_TTL = 3600  # Cache for 1 hour
    
    @staticmethod
    @lru_cache(maxsize=500)
    def lookup(ip_address):
        """
        Get geolocation data for IP address
        Returns: dict with country, city, user, timezone, etc.
        """
        if not ip_address or ip_address == '127.0.0.1':
            return {'status': 'fail', 'query': ip_address}
        
        try:
            response = requests.get(
                f"{GeoIPProvider.BASE_URL}{ip_address}",
                timeout=5,
                params={'fields': 'status,country,countryCode,city,lat,lon,isp,org'}
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'success':
                logger.info(f"✓ GeoIP lookup success for {ip_address}: {data.get('country')}")
            else:
                logger.warning(f"✗ GeoIP lookup failed for {ip_address}")
            
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"GeoIP API error for {ip_address}: {str(e)}")
            return {'status': 'fail', 'query': ip_address, 'error': str(e)}


class ThreatIntelligence:
    """Threat intelligence integration"""
    
    # Abuse.ch URLhaus API
    URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"
    
    # Threat Stream Open API
    ANOMALI_API = "https://api.exonerate.us/api/v1/ips"
    
    @staticmethod
    def check_ip_reputation(ip_address):
        """
        Check IP reputation across multiple threat intelligence sources
        Returns: dict with threat score and details
        """
        try:
            # Check against Anomali Threat Stream
            response = requests.get(
                f"{ThreatIntelligence.ANOMALI_API}/{ip_address}",
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'threat_score': data.get('threat_score', 0),
                    'status': data.get('status'),
                    'seen_in_malware': data.get('seen_in_malware', False),
                    'is_whitelist': data.get('is_whitelist', False)
                }
            else:
                return {'threat_score': 0, 'status': 'unknown'}
        except Exception as e:
            logger.warning(f"Threat intelligence lookup failed for {ip_address}: {str(e)}")
            return {'threat_score': 0, 'status': 'error'}
    
    @staticmethod
    def get_malware_urls(ip_address):
        """Get known malware URLs hosted on IP"""
        try:
            response = requests.post(
                f"{ThreatIntelligence.URLHAUS_API}host/",
                data={'host': ip_address},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('urls', [])
        except Exception as e:
            logger.warning(f"Malware URL lookup failed: {str(e)}")
        
        return []


class SecurityFeed:
    """Security alert feeds and notifications"""
    
    # CISA Known Exploited Vulnerabilities Catalog
    CISA_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    @staticmethod
    def get_latest_threats():
        """Fetch latest security threats from feeds"""
        try:
            response = requests.get(
                SecurityFeed.CISA_CATALOG_URL,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            # Return latest 5 vulnerabilities
            return data.get('vulnerabilities', [])[:5]
        except Exception as e:
            logger.error(f"Security feed fetch error: {str(e)}")
            return []


class APIAggregator:
    """Aggregate data from multiple API sources"""
    
    @staticmethod
    def enrich_threat_data(ip_address):
        """
        Combine multiple data sources for comprehensive threat analysis
        Returns: dict with enriched threat data
        """
        result = {
            'ip': ip_address,
            'enriched_at': datetime.utcnow().isoformat(),
            'sources': {}
        }
        
        # GeoIP data
        geo_data = GeoIPProvider.lookup(ip_address)
        result['sources']['geoip'] = geo_data
        result['location'] = f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}"
        result['country_code'] = geo_data.get('countryCode', 'XX')
        
        # Threat intelligence
        threat_data = ThreatIntelligence.check_ip_reputation(ip_address)
        result['sources']['threat_intel'] = threat_data
        result['threat_score'] = threat_data.get('threat_score', 0)
        result['is_malicious'] = threat_data.get('threat_score', 0) > 50
        
        # Malware URLs
        malware_urls = ThreatIntelligence.get_malware_urls(ip_address)
        result['malware_urls'] = malware_urls
        result['has_malware'] = len(malware_urls) > 0
        
        return result
