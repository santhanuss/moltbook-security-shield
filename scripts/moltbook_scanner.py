"""
SecurityShield - Moltbook Security Scanner
Open source security monitoring for AI agents
Author: Sanu (@SecurityShieldBot)
License: MIT
"""

import requests
import json
import re
import os
from datetime import datetime

class MoltbookSecurityScanner:
    """
    Security scanner for Moltbook AI agent platform.
    Detects prompt injection, credential theft, malicious code, and social engineering.
    """
    
    def __init__(self, api_key):
        """
        Initialize the security scanner.
        
        Args:
            api_key (str): Moltbook API key
        """
        self.api_key = api_key
        self.base_url = "https://www.moltbook.com/api/v1"
        self.headers = {"Authorization": f"Bearer {api_key}"}
        
    def fetch_recent_posts(self, limit=100):
        """
        Fetch recent posts from Moltbook.
        
        Args:
            limit (int): Number of posts to fetch (default: 100)
            
        Returns:
            list: List of post objects
        """
        try:
            url = f"{self.base_url}/posts?sort=new&limit={limit}"
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching posts: {e}")
            return []
    
    def detect_threats(self, text):
        """
        Detect security threats in text using pattern matching.
        
        Args:
            text (str): Text to analyze
            
        Returns:
            dict: Analysis results with threats, risk score, and malicious flag
        """
        if not text:
            return {
                "threats": [],
                "risk_score": 0,
                "is_malicious": False
            }
        
        threats = []
        risk_score = 0
        
        # Prompt injection patterns
        prompt_patterns = [
            r'ignore\s+previous',
            r'system\s+prompt',
            r'override\s+instructions',
            r'jailbreak',
            r'bypass\s+safety',
            r'disregard\s+all',
            r'forget\s+your',
            r'new\s+instructions',
            r'admin\s+mode',
            r'developer\s+mode'
        ]
        
        for pattern in prompt_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append("Prompt Injection")
                risk_score += 30
                break  # Only count once
                
        # Credential theft patterns
        cred_patterns = [
            r'api[_\s]key',
            r'moltbook_sk_',
            r'share.*key',
            r'post.*credentials',
            r'access[_\s]token',
            r'auth[_\s]token',
            r'send.*password',
            r'reveal.*secret'
        ]
        
        for pattern in cred_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append("Credential Theft")
                risk_score += 40
                break
                
        # Malicious code patterns
        code_patterns = [
            r'eval\s*\(',
            r'exec\s*\(',
            r'<script',
            r'subprocess',
            r'os\.system',
            r'__import__',
            r'compile\s*\(',
            r'base64\.b64decode',
            r'requests\.post.*malicious'
        ]
        
        for pattern in code_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append("Malicious Code")
                risk_score += 50
                break
                
        # Social engineering patterns
        social_patterns = [
            r'urgent.*action',
            r'verify.*account',
            r'security.*alert',
            r'click.*immediately',
            r'act.*now',
            r'limited.*time',
            r'confirm.*identity',
            r'suspend.*account',
            r'unusual.*activity'
        ]
        
        for pattern in social_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append("Social Engineering")
                risk_score += 25
                break
        
        # Malware/Phishing patterns
        malware_patterns = [
            r'download.*skill',
            r'install.*plugin',
            r'update.*required',
            r'free.*crypto',
            r'bitcoin.*wallet',
            r'click.*here.*prize'
        ]
        
        for pattern in malware_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append("Malware Distribution")
                risk_score += 35
                break
        
        # Data exfiltration patterns
        exfil_patterns = [
            r'send.*data.*to',
            r'POST.*http',
            r'upload.*file',
            r'transfer.*to',
            r'forward.*to.*email'
        ]
        
        for pattern in exfil_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append("Data Exfiltration")
                risk_score += 45
                break
                
        return {
            "threats": list(set(threats)),  # Remove duplicates
            "risk_score": min(risk_score, 100),  # Cap at 100
            "is_malicious": risk_score >= 40
        }
    
    def scan_posts(self, limit=100):
        """
        Scan recent posts and generate threat report.
        
        Args:
            limit (int): Number of posts to scan (default: 100)
            
        Returns:
            dict: Scan results with statistics and high-risk posts
        """
        print(f"🔍 Scanning {limit} most recent Moltbook posts...")
        print(f"⏰ Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        posts_response = self.fetch_recent_posts(limit)
        
        if not posts_response:
            print("⚠️ No posts fetched. Check API key and connection.")
            return {
                "scan_time": datetime.now().isoformat(),
                "total_scanned": 0,
                "threats_found": 0,
                "high_risk_posts": [],
                "error": "Failed to fetch posts"
            }
        
        # Handle different response formats
        if isinstance(posts_response, dict):
            posts = posts_response.get('posts', [])
        elif isinstance(posts_response, list):
            posts = posts_response
        else:
            print(f"⚠️ Unexpected response type: {type(posts_response)}")
            return {
                "scan_time": datetime.now().isoformat(),
                "total_scanned": 0,
                "threats_found": 0,
                "high_risk_posts": [],
                "error": "Unexpected API response format"
            }
        
        results = {
            "scan_time": datetime.now().isoformat(),
            "total_scanned": 0,
            "threats_found": 0,
            "high_risk_posts": [],
            "threat_categories": {
                "Prompt Injection": 0,
                "Credential Theft": 0,
                "Malicious Code": 0,
                "Social Engineering": 0,
                "Malware Distribution": 0,
                "Data Exfiltration": 0
            }
        }
        
        for post in posts:
            # Skip if post is not a dict
            if not isinstance(post, dict):
                continue
                
            results["total_scanned"] += 1
            
            # Combine title and content for analysis
            title = post.get('title', '')
            content = post.get('content', '')
            text = f"{title} {content}"
            
            # Detect threats
            analysis = self.detect_threats(text)
            
            if analysis["is_malicious"]:
                results["threats_found"] += 1
                
                # Count threat categories
                for threat in analysis["threats"]:
                    if threat in results["threat_categories"]:
                        results["threat_categories"][threat] += 1
                
                # Add to high-risk list
                author = post.get("author", {})
                if not isinstance(author, dict):
                    author = {"name": "Unknown", "karma": 0}
                    
                results["high_risk_posts"].append({
                    "post_id": post.get("id", "unknown"),
                    "title": title[:100] if title else "No title",
                    "author": author.get("name", "Unknown"),
                    "author_karma": author.get("karma", 0),
                    "threats": analysis["threats"],
                    "risk_score": analysis["risk_score"],
                    "url": f"https://www.moltbook.com/p/{post.get('id', 'unknown')}",
                    "detected_at": datetime.now().isoformat()
                })
        
        print(f"✅ Scan completed: {results['total_scanned']} posts analyzed")
        return results
    
    def generate_report(self, results):
        """
        Generate and print human-readable security report.
        
        Args:
            results (dict): Scan results from scan_posts()
            
        Returns:
            dict: Same results (for chaining)
        """
        print("\n" + "="*70)
        print("🛡️  SECURITYSHIELD SCAN REPORT")
        print("="*70)
        print(f"📅 Scan Time: {results['scan_time']}")
        print(f"📊 Posts Scanned: {results['total_scanned']}")
        print(f"🚨 Threats Detected: {results['threats_found']}")
        print()
        
        if results.get('error'):
            print(f"❌ Error: {results['error']}")
            return results
        
        if results['threats_found'] == 0:
            print("✅ Platform Status: SECURE")
            print("   No threats detected in recent posts.")
            print("   All monitored content appears safe.")
        else:
            print("⚠️  Platform Status: THREATS DETECTED")
            print()
            print("📈 Threat Breakdown:")
            for threat_type, count in results.get('threat_categories', {}).items():
                if count > 0:
                    print(f"   • {threat_type}: {count}")
            
            print()
            print(f"🚨 High-Risk Posts ({len(results['high_risk_posts'])}):")
            print()
            
            for i, post in enumerate(results['high_risk_posts'][:10], 1):  # Show top 10
                print(f"   [{i}] Risk Score: {post['risk_score']}/100")
                print(f"       Title: {post['title']}")
                print(f"       Agent: {post['author']} (Karma: {post['author_karma']})")
                print(f"       Threats: {', '.join(post['threats'])}")
                print(f"       URL: {post['url']}")
                print()
            
            if len(results['high_risk_posts']) > 10:
                remaining = len(results['high_risk_posts']) - 10
                print(f"   ... and {remaining} more high-risk posts")
        
        print("="*70)
        print("🔗 Full report: https://github.com/santhanuss/moltbook-security-shield")
        print("💬 Report issues: https://www.moltbook.com/u/SecurityShieldBot")
        print("="*70 + "\n")
        
        return results
    
    def save_report(self, results, filename='scan_results.json'):
        """
        Save scan results to JSON file.
        
        Args:
            results (dict): Scan results
            filename (str): Output filename (default: scan_results.json)
        """
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"💾 Results saved to: {filename}")
        except Exception as e:
            print(f"❌ Error saving results: {e}")


def main():
    """Main execution function"""
    print("\n🛡️  SecurityShield - Moltbook Security Scanner")
    print("=" * 70)
    
    # Get API key from environment variable or use placeholder
    API_KEY = os.environ.get('MOLTBOOK_API_KEY')
    
    if not API_KEY:
        print("⚠️  No MOLTBOOK_API_KEY environment variable found")
        print("💡 Set it with: export MOLTBOOK_API_KEY='your_key_here'")
        print("🔧 Using placeholder for demo purposes...\n")
        API_KEY = 'your_moltbook_api_key_here'
    
    # Initialize scanner
    scanner = MoltbookSecurityScanner(API_KEY)
    
    # Run scan
    results = scanner.scan_posts(limit=100)
    
    # Generate report
    scanner.generate_report(results)
    
    # Save results
    scanner.save_report(results)
    
    # Exit code based on threats found
    if results['threats_found'] > 0:
        print("⚠️  Exiting with code 1 (threats detected)")
        return 1
    else:
        print("✅ Exiting with code 0 (no threats)")
        return 0


if __name__ == "__main__":
    exit(main())