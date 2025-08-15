import re
import math
import datetime
from urllib.parse import urlparse
import sys
import subprocess
import socket

# Check if whois command is available
WHOIS_AVAILABLE = False

try:
    result = subprocess.run(['which', 'whois'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        WHOIS_AVAILABLE = True
        print("System whois command available")
    else:
        print("System whois command not found")
except Exception as e:
    print(f"Error checking for whois command: {str(e)}")

class PhishingScanner:
    def __init__(self):
        # Simple list of suspicious words commonly found in phishing sites
        self.suspicious_words = [
            'secure', 'signin', 'account', 'verify', 'update',
            'banking', 'payment', 'security', 'confirm', 'wallet',
            'password', 'authentication', 'credential', 'support', 'help',
            'official', 'verification', 'recover', 'restore', 'validate'
        ]
        
        # Popular brands that phishers often impersonate
        self.brand_names = [
            'paypal', 'amazon', 'facebook', 'apple', 'google',
            'netflix', 'instagram', 'twitter', 'linkedin', 'yahoo', 'gmail',
            'chase', 'bankofamerica', 'wellsfargo', 'citibank'
        ]
        
        # Suspicious TLDs (top-level domains) often used for phishing
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click']
        
        # Common domain patterns used in phishing
        self.high_risk_patterns = [
            r'secure-.*-login',
            r'login-.*-secure',
            r'account-.*-verification',
            r'verification-.*-account',
            r'banking-.*-security',
            r'security-.*-banking',
            r'payment-.*-confirm',
            r'confirm-.*-payment'
        ]
        
        # Legitimate domains for comparison
        self.legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'paypal.com',
            'microsoft.com', 'apple.com', 'twitter.com', 'instagram.com',
            'linkedin.com', 'yahoo.com', 'netflix.com'
        ]
        
        # KNOWN LEGITIMATE LOGIN DOMAINS (NEW)
        self.legitimate_login_domains = [
            'login.microsoftonline.com', 'accounts.google.com', 'login.yahoo.com',
            'login.live.com', 'auth.apple.com', 'login.facebook.com',
            'id.linkedin.com', 'auth.twitter.com', 'login.amazon.com',
            'signin.ebay.com', 'auth.paypal.com'
        ]
        
        # Common misspellings of popular domains
        self.common_misspellings = {
            'google': ['g00gle', 'g0ogle', 'googel', 'goggle'],
            'facebook': ['faceb00k', 'faceboook', 'faebook', 'facebok'],
            'amazon': ['amaz0n', 'amzon', 'amazzon'],
            'paypal': ['paypaI', 'paypa1', 'paypall']
        }
        
        # Phishing keywords commonly found in URL paths
        self.phishing_path_keywords = [
            'signin', 'verify', 'account', 'update', 'secure',
            'billing', 'payment', 'confirm', 'wallet', 'banking',
            'password', 'authentication', 'credential', 'support'
        ]
        
        # Settings for detection thresholds
        self.max_subdomains = 4  # Increased from 3
        self.max_domain_length = 45  # Increased from 40
        self.max_hyphens = 2  # Increased from 1
        self.high_entropy = 3.5
        self.new_domain_days = 90

    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Handle credentials in URL (user:pass@domain.com)
            if '@' in domain:
                domain = domain.split('@')[-1]
                
            return domain.lower()
        except:
            return None

    def has_credentials(self, url):
        """Check if URL contains credentials"""
        try:
            parsed = urlparse(url)
            return '@' in parsed.netloc and ':' in parsed.netloc
        except:
            return False

    def calculate_entropy(self, text):
        """Calculate randomness of text"""
        if not text:
            return 0
        
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        
        entropy = 0
        for count in counts.values():
            probability = count / len(text)
            entropy -= probability * math.log2(probability)
        
        return round(entropy, 2)

    def get_domain_age(self, domain):
        """Get domain age using system whois command"""
        if not WHOIS_AVAILABLE:
            return None, False
            
        try:
            # Run the whois command
            result = subprocess.run(['whois', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if result.returncode != 0:
                return None, False
            
            whois_output = result.stdout
            
            # Extract creation date using regex patterns
            date_patterns = [
                r'Creation Date:\s*(.+)',
                r'Created:\s*(.+)',
                r'Registered:\s*(.+)',
                r'Registration Date:\s*(.+)',
                r'created:\s*(.+)',
                r'registered:\s*(.+)',
                r'Creation Date:\s*(.+)',
                r'Registry Expiry Date:\s*(.+)',
                r'Expiry Date:\s*(.+)',
            ]
            
            creation_date_str = None
            for pattern in date_patterns:
                match = re.search(pattern, whois_output, re.IGNORECASE)
                if match:
                    creation_date_str = match.group(1).strip()
                    break
            
            if not creation_date_str:
                return None, False
            
            # Try to parse the date
            date_formats = [
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d',
                '%d-%b-%Y',
                '%Y%m%d',
                '%Y/%m/%d',
                '%m/%d/%Y',
                '%d.%m.%Y',
                '%b %d %H:%M:%S %Y %Z',
                '%d-%b-%Y %H:%M:%S %Z',
                '%Y-%m-%dT%H:%M:%S%z',
            ]
            
            parsed_date = None
            for fmt in date_formats:
                try:
                    date_str = creation_date_str
                    if 'T' in date_str and 'Z' in date_str and 'T' not in fmt:
                        date_str = date_str.split('T')[0]
                    if '.' in date_str and '%f' not in fmt:
                        date_str = date_str.split('.')[0]
                    if '+' in date_str and '%z' not in fmt:
                        date_str = date_str.split('+')[0]
                    
                    parsed_date = datetime.datetime.strptime(date_str, fmt)
                    break
                except ValueError:
                    continue
            
            if parsed_date:
                age = (datetime.datetime.now() - parsed_date).days
                is_new = age < self.new_domain_days
                return age, is_new
            else:
                return None, False
            
        except Exception:
            return None, False

    def check_domain_similarity(self, domain):
        """Check if domain is similar to legitimate domains"""
        domain_lower = domain.lower()
        
        # Remove 'www.' prefix if present
        if domain_lower.startswith('www.'):
            domain_lower = domain_lower[4:]
        
        # Check for common misspellings
        for correct_domain, misspellings in self.common_misspellings.items():
            for misspelling in misspellings:
                if misspelling in domain_lower:
                    return True, f"Possible misspelling of {correct_domain}.com"
        
        # Check if domain contains a legitimate domain but isn't exactly the same
        for legit_domain in self.legitimate_domains:
            if legit_domain in domain_lower and domain_lower != legit_domain:
                return True, legit_domain
        
        return False, None

    def check_homograph_attack(self, domain):
        """Check for potential homograph attacks (international characters)"""
        try:
            # Check if domain contains non-ASCII characters
            try:
                domain.encode('ascii')
                # If we get here, domain is ASCII only
                return False
            except UnicodeEncodeError:
                # Domain contains non-ASCII characters
                return True
        except:
            return False

    def check_dns_records(self, domain):
        """Check DNS records for suspicious indicators"""
        try:
            # Check if domain resolves to an IP address
            ip = socket.gethostbyname(domain)
            
            # Check if IP is in a suspicious range (e.g., known VPN/proxy ranges)
            # This is a simplified check - a real implementation would use a database of suspicious IP ranges
            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                first_octet = int(ip_parts[0])
                
                # Check for private IP ranges
                if (first_octet == 10) or \
                   (first_octet == 172 and 16 <= int(ip_parts[1]) <= 31) or \
                   (first_octet == 192 and int(ip_parts[1]) == 168):
                    return True, "Resolves to private IP range"
            
            return False, None
        except socket.gaierror:
            # Domain does not resolve
            return True, "Domain does not resolve"
        except:
            return False, None

    def check_url_redirects(self, url):
        """Check if URL redirects to another site"""
        try:
            # This is a simple check - in a real implementation, you would follow redirects
            parsed = urlparse(url)
            
            # Check for common redirect indicators in URL
            redirect_indicators = ['redirect', 'url', 'link', 'goto', 'to']
            path = parsed.path.lower()
            
            for indicator in redirect_indicators:
                if indicator in path:
                    return True
            
            # Check for URL parameters that might indicate redirects
            query = parsed.query.lower()
            redirect_params = ['url', 'redirect', 'link', 'goto', 'to', 'next']
            
            for param in redirect_params:
                if f"{param}=" in query:
                    return True
            
            return False
        except:
            return False

    def check_path_keywords(self, url):
        """Check for phishing keywords in URL path"""
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            found_keywords = []
            for keyword in self.phishing_path_keywords:
                if keyword in path:
                    found_keywords.append(keyword)
            
            return found_keywords
        except:
            return []

    def scan_url(self, url):
        """Scan a URL for phishing indicators"""
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Extract domain
        domain = self.extract_domain(url)
        if not domain:
            return {
                'url': url,
                'is_safe': False,
                'reasons': ['Invalid URL format'],
                'security_features': []
            }
        
        # Check if it's a known legitimate login domain (NEW CHECK)
        if domain in self.legitimate_login_domains:
            return {
                'url': url,
                'is_safe': True,
                'reasons': ['Known legitimate login domain'],
                'security_features': ['Uses HTTPS encryption']
            }
        
        # Initialize reasons and security features
        reasons = []
        security_features = []
        
        # Check for credentials in URL
        if self.has_credentials(url):
            reasons.append('Credentials in URL')
        
        # Check for IP address instead of domain name
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            reasons.append('Uses IP address instead of domain name')
        
        # Check for @ symbol in domain (excluding credentials case)
        if '@' in domain and not self.has_credentials(url):
            reasons.append('Contains @ symbol in domain')
        
        # Parse URL
        try:
            parsed = urlparse(url)
            
            # Check protocol
            if parsed.scheme == 'https':
                security_features.append('Uses HTTPS encryption')
            else:
                reasons.append('Does not use HTTPS encryption')
            
            # Check port
            if parsed.port and parsed.port not in [80, 443]:
                reasons.append(f'Uses unusual port number: {parsed.port}')
            
            # Check domain structure
            parts = domain.split('.')
            
            # Remove 'www' if present for subdomain count
            if parts[0] == 'www':
                parts = parts[1:]
            
            # Check for too many subdomains (updated threshold)
            if len(parts) > self.max_subdomains:
                reasons.append(f'Too many subdomains: {len(parts)-1}')
            
            # Check for overly long domain name (updated threshold)
            if len(domain) > self.max_domain_length:
                reasons.append(f'Domain name too long: {len(domain)} characters')
            
            # Check for too many hyphens (updated threshold)
            if domain.count('-') > self.max_hyphens:
                reasons.append(f'Too many hyphens: {domain.count("-")}')
            
            # Check TLD
            tld = '.' + parts[-1] if len(parts) > 1 else ''
            if tld in self.suspicious_tlds:
                reasons.append(f'Uses suspicious TLD: {tld}')
            
            # Check for high-risk patterns
            domain_lower = domain.lower()
            for pattern in self.high_risk_patterns:
                if re.search(pattern, domain_lower):
                    reasons.append('Contains high-risk pattern')
                    break
            
            # Check for suspicious words (MODIFIED - less sensitive)
            found_suspicious_words = []
            for word in self.suspicious_words:
                if word in domain_lower:
                    # Only flag if combined with other suspicious indicators
                    found_suspicious_words.append(word)
            
            # Check for brand names combined with suspicious words (MODIFIED)
            found_brand_names = []
            for brand in self.brand_names:
                if brand in domain_lower:
                    found_brand_names.append(brand)
            
            # Only flag brand + suspicious words if it's not a known legitimate domain pattern
            if found_brand_names and found_suspicious_words and domain not in self.legitimate_login_domains:
                reasons.append(f'Combines brand names with suspicious words: {", ".join(found_brand_names)} + {", ".join(found_suspicious_words)}')
            
            # Check entropy (randomness)
            entropy = self.calculate_entropy(domain)
            if entropy > self.high_entropy:
                reasons.append(f'Domain name looks random (high entropy: {entropy})')
            
            # Check domain age
            age, is_new = self.get_domain_age(domain)
            if age is not None:
                if is_new:
                    reasons.append(f'Domain is newly registered: {age} days old')
                else:
                    security_features.append(f'Established domain: {age} days old')
            else:
                reasons.append('Could not determine domain age')
            
            # Check if domain is similar to legitimate domains
            is_similar, similar_to = self.check_domain_similarity(domain)
            if is_similar:
                reasons.append(f'Similar to legitimate domain: {similar_to}')
            
            # Check for homograph attacks
            if self.check_homograph_attack(domain):
                reasons.append('Contains international characters (possible homograph attack)')
            
            # Check DNS records
            dns_suspicious, dns_reason = self.check_dns_records(domain)
            if dns_suspicious:
                reasons.append(f'DNS issue: {dns_reason}')
            
            # Check for URL redirects
            if self.check_url_redirects(url):
                reasons.append('URL may redirect to another site')
            
            # Check for phishing keywords in URL path
            path_keywords = self.check_path_keywords(url)
            if path_keywords:
                reasons.append(f'Suspicious path keywords: {", ".join(path_keywords)}')
            
        except Exception as e:
            print(f"Error parsing URL: {str(e)}")
            reasons.append('URL parsing error')
        
        # Determine if safe based on presence of suspicious indicators
        # More lenient for legitimate domains
        is_safe = len(reasons) <= 1
        
        return {
            'url': url,
            'domain': domain,
            'is_safe': is_safe,
            'reasons': reasons,
            'security_features': security_features
        }

    def display_result(self, result):
        """Display scan results"""
        print("\n" + "=" * 60)
        print("PHISHING SCAN RESULTS")
        print("=" * 60)
        print(f"URL: {result['url']}")
        print(f"Domain: {result.get('domain', 'N/A')}")
        print()
        
        # Display result
        if result['is_safe']:
            print("✅ SAFE TO VISIT")
            print("   This URL appears to be legitimate")
        else:
            print("🚨 POTENTIAL PHISHING")
            print("   This URL shows signs of being a phishing attempt")
        
        # Display reasons
        if result['reasons']:
            print("\nSuspicious Indicators:")
            for reason in result['reasons']:
                print(f"   • {reason}")
        
        # Display security features
        if result['security_features']:
            print("\nSecurity Features:")
            for feature in result['security_features']:
                print(f"   ✓ {feature}")
        
        print("=" * 60)

def main_menu(scanner):
    """Display main menu"""
    while True:
        print("\n" + "=" * 40)
        print("PHISHING SCANNER")
        print("=" * 40)
        print("1. Scan URL")
        print("2. Exit")
        print("=" * 40)
        
        choice = input("Enter your choice (1-2): ")
        
        if choice == '1':
            scan_url(scanner)
        elif choice == '2':
            print("\nThank you for using the Phishing Scanner!")
            break
        else:
            print("Invalid choice. Please enter 1 or 2.")

def scan_url(scanner):
    """Handle URL scanning"""
    print("\n" + "=" * 40)
    print("SCAN URL")
    print("=" * 40)
    
    url = input("Enter URL to scan: ").strip()
    
    if not url:
        print("No URL entered.")
        return
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print("\nScanning...")
    
    # Scan the URL
    result = scanner.scan_url(url)
    
    # Display results
    scanner.display_result(result)
    
    input("\nPress Enter to continue...")

def main():
    """Main function"""
    # Display system command availability
    print("\n" + "=" * 60)
    print("SYSTEM COMMAND AVAILABILITY CHECK")
    print("=" * 60)
    
    if WHOIS_AVAILABLE:
        print("✓ System whois command available")
    else:
        print("✗ System whois command not available")
        print("   Install with: sudo apt-get install whois (Debian/Ubuntu)")
        print("   or: sudo yum install whois (RHEL/CentOS)")
    
    if not WHOIS_AVAILABLE:
        print("\n⚠️  Domain age checking will be limited.")
        print("   Install the system whois command for full domain age checking.")
    
    # Create scanner
    scanner = PhishingScanner()
    
    # Display welcome message
    print("""
    PHISHING SCANNER
    
    Welcome to the Phishing Scanner!
    This tool helps detect phishing websites.
    
    Note: For educational purposes only.
""")
    
    # Show menu
    main_menu(scanner)

if __name__ == "__main__":
    main()
