#!/usr/bin/env python3
"""
Shortecho - Web Technology Detection Tool
Identifies frameworks, libraries, servers, and technologies used by web applications
"""

import requests
import re
import json
import argparse
import os
from urllib.parse import urljoin
from typing import Dict, List
from collections import defaultdict

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    @staticmethod
    def disable():
        Colors.HEADER = ''
        Colors.OKBLUE = ''
        Colors.OKCYAN = ''
        Colors.OKGREEN = ''
        Colors.WARNING = ''
        Colors.FAIL = ''
        Colors.ENDC = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''

class TechFingerprinter:
    def __init__(self, signatures_file='signatures.json'):
        self.signatures = self.load_signatures(signatures_file)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def load_signatures(self, signatures_file):
        """Load technology signatures from JSON file"""
        if not os.path.exists(signatures_file):
            print(f"{Colors.FAIL}[!] Error: Signature file '{signatures_file}' not found!{Colors.ENDC}")
            print(f"{Colors.WARNING}[*] Please ensure 'signatures.json' is in the same directory as this script.{Colors.ENDC}")
            exit(1)
        
        try:
            with open(signatures_file, 'r', encoding='utf-8') as f:
                signatures = json.load(f)
                print(f"{Colors.OKGREEN}[+] Loaded {len(signatures)} technology signatures{Colors.ENDC}")
                return signatures
        except json.JSONDecodeError as e:
            print(f"{Colors.FAIL}[!] Error parsing JSON file: {e}{Colors.ENDC}")
            exit(1)
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error loading signatures: {e}{Colors.ENDC}")
            exit(1)
    
    def fetch_target(self, url: str, timeout: int = 10) -> Dict:
        """Fetch target URL and return response data"""
        try:
            response = self.session.get(url, timeout=timeout, allow_redirects=True)
            return {
                'url': response.url,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'html': response.text,
                'cookies': {cookie.name: cookie.value for cookie in response.cookies}
            }
        except requests.RequestException as e:
            print(f"{Colors.FAIL}[!] Error fetching {url}: {e}{Colors.ENDC}")
            return None
    
    def check_headers(self, headers: Dict, patterns: Dict) -> List[tuple]:
        """Check HTTP headers for technology signatures"""
        matches = []
        for header_name, pattern in patterns.items():
            if header_name in headers:
                header_value = headers[header_name]
                if pattern:
                    match = re.search(pattern, header_value, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.groups() else None
                        matches.append((True, version))
                else:
                    matches.append((True, None))
        return matches
    
    def check_html(self, html: str, patterns: List[str]) -> List[tuple]:
        """Check HTML content for technology signatures"""
        matches = []
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else None
                matches.append((True, version))
        return matches
    
    def check_scripts(self, html: str, scripts: List[str]) -> List[tuple]:
        """Check for JavaScript file patterns"""
        matches = []
        script_tags = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        
        for script_pattern in scripts:
            for script_url in script_tags:
                match = re.search(script_pattern, script_url, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else None
                    matches.append((True, version))
        return matches
    
    def check_cookies(self, cookies: Dict, patterns: List[str]) -> bool:
        """Check cookies for technology signatures"""
        for pattern in patterns:
            for cookie_name in cookies.keys():
                if re.search(pattern, cookie_name, re.IGNORECASE):
                    return True
        return False
    
    def check_url_patterns(self, base_url: str, patterns: List[str]) -> List[str]:
        """Check if specific URLs exist (active detection)"""
        found = []
        for pattern in patterns:
            url = urljoin(base_url, pattern)
            try:
                response = self.session.head(url, timeout=5, allow_redirects=True)
                if response.status_code != 404:
                    found.append(pattern)
            except:
                pass
        return found
    
    def detect_technologies(self, response_data: Dict, active_scan: bool = False) -> Dict:
        """Main detection logic"""
        detected = defaultdict(lambda: {'confidence': 0, 'version': None, 'categories': []})
        
        for tech_name, signatures in self.signatures.items():
            confidence = 0
            version = None
            
            # Check headers
            if 'headers' in signatures:
                header_matches = self.check_headers(response_data['headers'], signatures['headers'])
                if header_matches:
                    confidence += 30 * len(header_matches)
                    for match, ver in header_matches:
                        if ver:
                            version = ver
            
            # Check HTML patterns
            if 'html' in signatures:
                html_matches = self.check_html(response_data['html'], signatures['html'])
                if html_matches:
                    confidence += 20 * len(html_matches)
                    for match, ver in html_matches:
                        if ver:
                            version = ver
            
            # Check scripts
            if 'scripts' in signatures:
                script_matches = self.check_scripts(response_data['html'], signatures['scripts'])
                if script_matches:
                    confidence += 25 * len(script_matches)
                    for match, ver in script_matches:
                        if ver:
                            version = ver
            
            # Check cookies
            if 'cookies' in signatures:
                if self.check_cookies(response_data['cookies'], signatures['cookies']):
                    confidence += 20
            
            # Active URL checking
            if active_scan and 'url_patterns' in signatures:
                found_urls = self.check_url_patterns(response_data['url'], signatures['url_patterns'])
                if found_urls:
                    confidence += 30 * len(found_urls)
            
            # Cap confidence at 100
            confidence = min(confidence, 100)
            
            if confidence > 0:
                detected[tech_name]['confidence'] = confidence
                detected[tech_name]['version'] = version
                detected[tech_name]['categories'] = signatures.get('categories', [])
        
        # Handle implied technologies
        for tech_name in list(detected.keys()):
            if 'implies' in self.signatures[tech_name]:
                for implied_tech in self.signatures[tech_name]['implies']:
                    if implied_tech in self.signatures and implied_tech not in detected:
                        detected[implied_tech]['confidence'] = 50
                        detected[implied_tech]['categories'] = self.signatures[implied_tech].get('categories', [])
        
        return dict(detected)
    
    def scan(self, url: str, active_scan: bool = False, min_confidence: int = 30) -> Dict:
        """Perform complete technology scan"""
        print(f"{Colors.OKCYAN}[*] Scanning: {url}{Colors.ENDC}")
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Fetch target
        response_data = self.fetch_target(url)
        if not response_data:
            return None
        
        print(f"{Colors.OKGREEN}[+] Target responded with status code: {response_data['status_code']}{Colors.ENDC}")
        
        # Detect technologies
        detected = self.detect_technologies(response_data, active_scan)
        
        # Filter by minimum confidence
        detected = {k: v for k, v in detected.items() if v['confidence'] >= min_confidence}
        
        # Sort by confidence
        detected = dict(sorted(detected.items(), key=lambda x: x[1]['confidence'], reverse=True))
        
        return {
            'url': response_data['url'],
            'status_code': response_data['status_code'],
            'technologies': detected
        }
    
    def print_results(self, results: Dict):
        """Print scan results in readable format with colors"""
        if not results:
            print(f"{Colors.FAIL}[!] No results to display{Colors.ENDC}")
            return
        
        print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}Target:{Colors.ENDC} {Colors.OKCYAN}{results['url']}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}Status:{Colors.ENDC} {self._status_color(results['status_code'])}{results['status_code']}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
        
        if not results['technologies']:
            print(f"{Colors.WARNING}[!] No technologies detected{Colors.ENDC}")
            return
        
        # Group by category
        by_category = defaultdict(list)
        for tech, data in results['technologies'].items():
            for category in data['categories']:
                by_category[category].append((tech, data))
            if not data['categories']:
                by_category['Other'].append((tech, data))
        
        # Print by category with colors
        for category in sorted(by_category.keys()):
            category_color = self._category_color(category)
            print(f"\n{category_color}{Colors.BOLD}[{category}]{Colors.ENDC}")
            
            for tech, data in sorted(by_category[category], key=lambda x: x[1]['confidence'], reverse=True):
                version_str = f" {Colors.OKCYAN}(v{data['version']}){Colors.ENDC}" if data['version'] else ""
                confidence = data['confidence']
                confidence_color = self._confidence_color(confidence)
                confidence_str = f"{confidence_color}{confidence}%{Colors.ENDC}"
                
                print(f"  {Colors.BOLD}•{Colors.ENDC} {Colors.BOLD}{tech}{Colors.ENDC}{version_str} - Confidence: {confidence_str}")
        
        print(f"\n{Colors.BOLD}{'='*70}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{Colors.BOLD}Total technologies detected: {len(results['technologies'])}{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    def _status_color(self, status_code: int) -> str:
        """Return color based on HTTP status code"""
        if 200 <= status_code < 300:
            return Colors.OKGREEN
        elif 300 <= status_code < 400:
            return Colors.OKCYAN
        elif 400 <= status_code < 500:
            return Colors.WARNING
        else:
            return Colors.FAIL
    
    def _confidence_color(self, confidence: int) -> str:
        """Return color based on confidence level"""
        if confidence >= 80:
            return Colors.OKGREEN
        elif confidence >= 60:
            return Colors.OKCYAN
        elif confidence >= 40:
            return Colors.WARNING
        else:
            return Colors.FAIL
    
    def _category_color(self, category: str) -> str:
        """Return color based on category type"""
        category_colors = {
            'CMS': Colors.HEADER,
            'JavaScript Framework': Colors.OKBLUE,
            'JavaScript Library': Colors.OKCYAN,
            'CSS Framework': Colors.OKGREEN,
            'Web Framework': Colors.HEADER,
            'Programming Language': Colors.WARNING,
            'Web Server': Colors.FAIL,
            'CDN': Colors.OKCYAN,
            'WAF': Colors.FAIL,
            'Security': Colors.FAIL,
            'Analytics': Colors.WARNING,
            'Hosting': Colors.OKCYAN,
            'E-commerce': Colors.HEADER,
            'Database': Colors.HEADER,
            'Payment Processor': Colors.WARNING,
            'Build Tool': Colors.OKBLUE,
        }
        return category_colors.get(category, Colors.OKBLUE)
    
    def export_json(self, results: Dict, filename: str):
        """Export results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{Colors.OKGREEN}[+] Results exported to {filename}{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description='Tech Stack Fingerprinter - Identify web technologies',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 shortecho.py https://example.com
  python3 shortecho.py https://example.com --active
  python3 shortecho.py https://example.com --output results.json
  python3 shortecho.py https://example.com --min-confidence 50
  python3 shortecho.py https://example.com --no-color
  python3 shortecho.py https://example.com --signatures custom.json
        """
    )
    
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-a', '--active', action='store_true',
                       help='Perform active scanning (check specific URLs)')
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    parser.add_argument('-s', '--signatures', default='signatures.json',
                       help='Path to signatures JSON file (default: signatures.json)')
    parser.add_argument('-m', '--min-confidence', type=int, default=30,
                       help='Minimum confidence threshold (default: 30)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        Colors.disable()
    
    # Initialize fingerprinter
    fingerprinter = TechFingerprinter(args.signatures)
    
    # Scan target
    results = fingerprinter.scan(
        args.url,
        active_scan=args.active,
        min_confidence=args.min_confidence
    )
    
    if results:
        # Print results
        fingerprinter.print_results(results)
        
        # Export if requested
        if args.output:
            fingerprinter.export_json(results, args.output)


if __name__ == '__main__':
    main()
