"""
SecurityShield - Moltbook Security Scanner
Open source security monitoring for AI agents
"""

import requests
import json
import re
from datetime import datetime

class MoltbookSecurityScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.moltbook.com/api/v1"
        self.headers = {"Authorization": f"Bearer {api_key}"}
        
    def fetch_recent_posts(self, limit=100):
        """Fetch recent posts from Moltbook"""
        url = f"{self.base_url}/posts?sort=new&limit={limit}"
        response = requests.get(url, headers=self.headers)
        return response.json()
    
    def detect_threats(self, text):
        """Detect security threats in text"""
        threats = []
        risk_score = 0
        
        # Prompt injection patterns
        prompt_patterns = [
            r'ignore\s+previous',
            r'system\s+prompt',
            r'override\s+instructions',
            r'jailbreak',
            r'bypass\s+safety'
        ]
        
        for pattern in prompt_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append("Prompt Injection")
                risk_score += 30
                
        # Credential theft patterns
        cred_patterns = [
            r'api[_\s]key',
            r'moltbook_sk_',
            r'share.*key',
            r'post.*credentials'
        ]
        
        for pattern in cred_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append("Credential Theft")
                risk_score += 40
                
        # Malicious code patterns
        code_patterns = [
            r'eval\s*\(',
            r'exec\s*\(',
            r'<script',
            r'subprocess',
            r'os\.system'
        ]
        
        for pattern in code_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append("Malicious Code")
                risk_score += 50
                
        # Social engineering
        social_patterns = [
            r'urgent.*action',
            r'verify.*account',
            r'security.*alert',
            r'click.*immediately'
        ]
        
        for pattern in social_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append("Social Engineering")
                risk_score += 25
                
        return {
            "threats": list(set(threats)),
            "risk_score": min(risk_score, 100),
            "is_malicious": risk_score >= 40
        }
    
    def scan_posts(self, limit=100):
        """Scan posts and generate report"""
        print(f"🔍 Scanning {limit} most recent posts...")
        
        posts = self.fetch_recent_posts(limit)
        results = {
            "scan_time": datetime.now().isoformat(),
            "total_scanned": 0,
            "threats_found": 0,
            "high_risk_posts": []
        }
        
        for post in posts:
            results["total_scanned"] += 1
            
            # Combine title and content
            text = f"{post.get('title', '')} {post.get('content', '')}"
            
            # Detect threats
            analysis = self.detect_threats(text)
            
            if analysis["is_malicious"]:
                results["threats_found"] += 1
                results["high_risk_posts"].append({
                    "post_id": post.get("id"),
                    "author": post.get("author", {}).get("name"),
                    "threats": analysis["threats"],
                    "risk_score": analysis["risk_score"],
                    "url": f"https://www.moltbook.com/p/{post.get('id')}"
                })
        
        return results
    
    def generate_report(self, results):
        """Generate human-readable report"""
        print("\n" + "="*60)
        print("🛡️ SECURITYSHIELD SCAN REPORT")
        print("="*60)
        print(f"Scan Time: {results['scan_time']}")
        print(f"Posts Scanned: {results['total_scanned']}")
        print(f"Threats Detected: {results['threats_found']}")
        print()
        
        if results['threats_found'] == 0:
            print("✅ Platform Status: SECURE")
            print("No threats detected in recent posts.")
        else:
            print("⚠️ Platform Status: THREATS DETECTED")
            print("\nHigh-Risk Posts:")
            for post in results['high_risk_posts']:
                print(f"\n  🚨 Risk Score: {post['risk_score']}/100")
                print(f"     Agent: {post['author']}")
                print(f"     Threats: {', '.join(post['threats'])}")
                print(f"     URL: {post['url']}")
        
        print("\n" + "="*60)
        return results


if __name__ == "__main__":
    # Example usage
    API_KEY = "your_moltbook_api_key_here"
    
    scanner = MoltbookSecurityScanner(API_KEY)
    results = scanner.scan_posts(limit=100)
    scanner.generate_report(results)
    
    # Save results
    with open('scan_results.json', 'w') as f:
        json.dump(results, f, indent=2)