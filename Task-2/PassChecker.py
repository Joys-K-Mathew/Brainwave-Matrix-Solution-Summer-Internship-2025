import requests
import hashlib
import re
import sys
import json
import os
import math

def main():
    """Main function to run the password checker"""
    print("🔐 Password Strength Checker (NIST 800-63B v2.0)")
    print("=" * 45)
    
    # Load common passwords
    common_passwords = load_passwords()
    
    while True:
        # Get password from user
        password = input("\nEnter your password to check: ").strip()
        
        if not password:
            print("❌ Please enter a password.")
            continue
        
        # Check password strength
        score, feedback = check_password_strength(password, common_passwords)
        
        # Check if breached
        print("\n🔍 Checking breach database...")
        is_breached = check_breached(password)
        
        # Show results
        show_results(score, feedback, is_breached)
        
        # Ask to continue
        another = input("\nCheck another password? (y/n): ").lower()
        if another != 'y':
            print("\nThank you for using the Password Strength Checker!")
            break

def load_passwords():
    """Load common passwords from GitHub or cache"""
    print("📥 Loading security data...")
    
    # Try to load from cache file
    cache_file = "password_cache.json"
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
                print("📦 Loaded from cache")
                return set(data['passwords'])
        except:
            pass
    
    # Download from GitHub
    passwords = set()
    urls = [
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt',
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt'
    ]
    
    for url in urls:
        try:
            print(f"📥 Downloading {url.split('/')[-1]}...")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                for line in response.text.strip().split('\n'):
                    if line.strip():
                        passwords.add(line.strip().lower())
                print(f"  ✓ Got {len(passwords)} passwords")
        except:
            print("  ✗ Download failed")
    
    # Save to cache
    try:
        with open(cache_file, 'w') as f:
            json.dump({'passwords': list(passwords)}, f)
        print("💾 Saved to cache")
    except:
        pass
    
    # Fallback if download failed
    if not passwords:
        print("⚠️ Using basic password list")
        passwords = {'password', '123456', '12345678', '123456789', 'qwerty', 'abc123'}
    
    return passwords

def check_password_strength(password, common_passwords):
    """Check password strength using NIST guidelines"""
    score = 0
    feedback = []
    
    # Check if it's a common password
    if password.lower() in common_passwords:
        return 0, ["❌ This is a common password", "Choose something unique"]
    
    # Check length (most important factor)
    length = len(password)
    if length >= 14:
        score += 70
        feedback.append("✅ Excellent length (14+ characters)")
    elif length >= 12:
        score += 60
        feedback.append("✅ Good length (12+ characters)")
    elif length >= 10:
        score += 50
        feedback.append("✅ Acceptable length (10+ characters)")
    elif length >= 8:
        score += 40
        feedback.append("⚠️ Minimum length (8 characters)")
    else:
        return 0, ["❌ Too short! Use at least 8 characters"]
    
    # Check character variety
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    variety_count = sum([has_upper, has_lower, has_digit, has_special])
    
    if variety_count == 4:
        score += 20
        feedback.append("✅ Uses all character types")
    elif variety_count == 3:
        score += 15
        feedback.append("✅ Good character variety")
    elif variety_count == 2:
        score += 10
        feedback.append("⚠️ Limited character variety")
    else:
        score += 5
        feedback.append("❌ Very limited character variety")
    
    # Check entropy (unpredictability)
    entropy = calculate_entropy(password)
    if entropy >= 60:
        score += 10
        feedback.append("✅ Very unpredictable")
    elif entropy >= 40:
        score += 7
        feedback.append("✅ Good unpredictability")
    elif entropy >= 20:
        score += 5
        feedback.append("⚠️ Somewhat predictable")
    else:
        feedback.append("❌ Very predictable")
    
    # Check for bad patterns
    penalties = 0
    
    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        penalties += 10
        feedback.append("❌ Has repeated characters")
    
    # Sequential characters
    sequential = 'abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789'
    if re.search(sequential, password.lower()):
        penalties += 10
        feedback.append("❌ Has sequential characters")
    
    # Keyboard patterns
    keyboard = 'qwerty|asdfgh|zxcvbn|qaz|wsx|edc|rfv|tgb|yhn|ujm|ik|ol'
    if re.search(keyboard, password.lower()):
        penalties += 10
        feedback.append("❌ Has keyboard patterns")
    
    # Apply penalties
    score = max(0, score - penalties)
    
    return score, feedback

def calculate_entropy(password):
    """Calculate how unpredictable the password is"""
    if not password:
        return 0
    
    # Count different types of characters
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26  # lowercase letters
    if re.search(r'[A-Z]', password):
        charset_size += 26  # uppercase letters
    if re.search(r'[0-9]', password):
        charset_size += 10  # numbers
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        charset_size += 32  # symbols
    
    # Calculate entropy
    if charset_size > 0:
        return len(password) * math.log2(charset_size)
    return 0

def check_breached(password):
    """Check if password has been in a data breach"""
    try:
        # Create hash of password
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        # Check HaveIBeenPwned database
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            return suffix in response.text
    except:
        print("  ⚠️ Could not check breach database")
    
    return False

def show_results(score, feedback, is_breached):
    """Display the results to the user"""
    print("\n" + "=" * 45)
    print("RESULTS (NIST 800-63B v2.0)")
    print("=" * 45)
    
    # Check if breached first
    if is_breached:
        print("🚨 BREACHED PASSWORD!")
        print("This password has been found in data breaches.")
        print("Choose a different password immediately.")
        return
    
    # Show score and strength level
    print(f"Strength Score: {score}/100")
    
    if score >= 80:
        print("✅ Very Strong (NIST Compliant)")
    elif score >= 60:
        print("✅ Strong (NIST Compliant)")
    elif score >= 40:
        print("⚠️ Moderate (Needs Improvement)")
    elif score >= 20:
        print("❌ Weak (Not Recommended)")
    else:
        print("❌ Very Weak (Unacceptable)")
    
    # Show feedback
    print("\nAnalysis:")
    for item in feedback:
        print(f"• {item}")
    
    # Show how to improve
    if score < 100:
        print("\n🎯 TO GET A PERFECT SCORE:")
        improvements = get_improvements(score)
        for improvement in improvements:
            print(f"• {improvement}")

def get_improvements(score):
    """Get suggestions to improve password score"""
    improvements = []
    
    # Length suggestions
    if score < 70:
        improvements.append("Use 14+ characters for maximum strength")
    elif score < 60:
        improvements.append("Use 12+ characters")
    elif score < 50:
        improvements.append("Use 10+ characters")
    
    # Character variety suggestions
    if score < 80:
        improvements.append("Mix uppercase, lowercase, numbers, and symbols")
    
    # Pattern suggestions
    if score < 70:
        improvements.append("Avoid repeated characters (aaa, 111)")
        improvements.append("Avoid sequential patterns (abc, 123)")
        improvements.append("Avoid keyboard patterns (qwerty, asdf)")
    
    # Unpredictability suggestions
    if score < 60:
        improvements.append("Use random characters instead of words")
    
    return improvements

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nGoodbye!")
        sys.exit(0)
