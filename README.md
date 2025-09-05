<h1 align="center">Brainwave-Matrix-Solution-Summer-Internship-2025</h1>

Welcome to the repository for my Summer 2025 internship at Brainwave Matrix Solution as **Cybersecurity Intern**. This document serves as a comprehensive overview of my journey, the projects I contributed to, the skills I developed, and my key takeaways from this valuable experience.

> [!WARNING]
> The code and tools in this repository are developed for educational and research purposes only as part of my internship. They are intended to help cybersecurity professionals and students understand potential vulnerabilities and defense mechanisms. Any actions and or activities related to the material contained within this repository are solely your responsibility. I will not be held responsible in the event any criminal charges be brought against any individuals misusing the information in this repository to break the law.


# 📂 Projects
Below is a summary of the key projects I was involved in during my internship.

<details>
<summary><h2>Task 1: Phishing Link Scanner using Python</h2></summary>

### Task: 
The goal of this project is to develop a tool in Python that can analyze URLs to detect potential phishing attempts. The scanner will check for common characteristics of malicious links, such as suspicious keywords, URL shortening, and domain age, to flag them as safe or unsafe.

#### Tool Overview
The Phishing Link Scanner is a command-line tool written in Python designed to analyze URLs and identify potential phishing threats. By examining various characteristics of a link, such as its structure, domain age, and keywords, the tool provides a risk assessment, flagging URLs as either "SAFE TO VISIT" ✅ or "POTENTIAL PHISHING" 🚨. It's an educational and practical first line of defense against malicious links.

### How to Run the Tool
### Prerequisites:

- **Python 3**: Ensure you have Python 3 installed.
- **whois command**: This tool relies on the system's whois command for checking domain age, as direct Python libraries can be unreliable. To install it on a Debian-based Linux system (like Ubuntu), run:

```
sudo apt-get install whois
```
### Steps:

- **Download the Code**: Download the code "phishscanner.py" from the folder "Task-1" int your computer.
- **Open a Terminal**: Open your command prompt or terminal.
- **Navigate to the Directory**: Use the cd command to navigate to the folder where you saved scanner.py.
- **Run the Script**: Execute the script using the Python interpreter:

```
python phishscanner.py
```
- **Follow the Menu**: The tool will start and display a menu. Choose option 1 to scan a URL.

### What is Phishing? 🎣
Phishing is a type of cyberattack where criminals trick individuals into revealing sensitive information (like passwords or credit card numbers) by disguising themselves as a trustworthy entity. This is dangerous as it can lead to identity theft, financial loss, and malware installation.

### How Does This Tool Help?
This scanner acts as an automated detective 🕵️. It quickly analyzes a suspicious link against a list of known red flags, empowering you to make an informed decision before clicking and reducing your risk of falling victim to a phishing attack.

### Tips to Avoid Phishing 🛡️
- **Hover Before You Click**: Always hover your mouse over a link to see the actual destination URL in the bottom corner of your browser. Make sure it matches the expected website.
- **Check the Sender**: Scrutinize the sender's email address. Attackers often use addresses that are slightly different from the official ones (e.g., support@paypal-security.com instead of support@paypal.com).
- **Look for Errors**: Be wary of emails with spelling mistakes, grammatical errors, or unprofessional formatting. Legitimate companies usually have high standards for their communications.
- **Beware of Urgency**: Phishing attempts often create a false sense of urgency (e.g., "Your account will be suspended in 24 hours!"). This is a tactic to make you act quickly without thinking.
- **Go Directly to the Source**: If you receive a suspicious request, don't click the link. Instead, open a new browser window and type the official website address yourself to log in and check for any alerts.
- **Use Strong Security**: Enable two-factor authentication (2FA) on all your important accounts. This adds an extra layer of security even if your password is stolen.

### Checks Used in the Scanner
- **HTTPS Encryption**: Ensures the connection is secure. Lack of https:// is a major red flag.
- **Domain Age**: Phishing sites are often newly created. The tool checks the domain's registration date, as older domains are generally more trustworthy.
- **Credentials in URL**: Detects if a username and password are included in the URL, which is a highly suspicious practice.
- **IP Address as Domain**: Flags URLs that use a raw IP address instead of a a domain name, a common tactic for malicious sites.
- **Suspicious Keywords & Patterns**: Looks for words like secure, login, verify combined with brand names to create a false sense of security.
- **URL Structure**:
  - Checks for an excessive number of subdomains, long domain names, or too many hyphens.
  - Flags the use of non-standard port numbers.
- **High Entropy**: Calculates the "randomness" of the domain. Highly random names often indicate an auto-generated, malicious domain.
- **Domain Similarity & Misspellings**: Detects "typosquatting" (e.g., g00gle.com instead of google.com).
- **Homograph Attacks**: Identifies international characters that look like standard letters to create visually deceptive domains.
- **Suspicious Path & Redirects**: Scans the full URL path for phishing keywords (e.g., /billing/, /confirm/) and indicators of automatic redirects.
- **DNS Records**: Confirms the domain points to a valid IP address.
### Links that are used to test this tool
#### Legitimate URLs (Should be safe)

- `https://www.google.com`  
  *Basic legitimate domain*

- `https://login.microsoftonline.com`  
  *Known legitimate login domain*

- `https://www.amazon.com`  
  *Established e-commerce site*

#### Suspicious TLDs

- `http://secure-login.tk`  
  *Uses suspicious .tk TLD*

- `http://banking-update.ml`  
  *Uses suspicious .ml TLD*

#### Brand Impersonation

- `http://secure-paypal-login.com`  
  *Brand impersonation + suspicious words*

- `http://amazon-verification.xyz`  
  *Brand impersonation + suspicious TLD*

#### High Entropy (Random Domains)

- `http://xj2h8k9l3p0q.com`  
  *Random-looking domain name*

- `http://a1b2c3d4e5f6g7h8.com`  
  *High entropy domain*

#### Structural Issues

- `http://user:pass@example.com`  
  *Credentials in URL*

- `http://a.b.c.d.e.example.com`  
  *Too many subdomains*

- `http://this-is-a-very-long-domain-name-with-many-hyphens.com`  
  *Excessive hyphens*

#### Homograph & Typosquatting

- `http://g00gle.com`  
  *Common misspelling of Google*

- `http://xn--google-9ua.com`  
  *Homograph attack (Punycode representation)*

#### Network & Path Issues

- `http://192.168.1.1/login`  
  *Uses IP address instead of domain*

#### Additional Test Cases

- `http://example.com/verify-account`  
  *Suspicious path keywords*

- `http://bit.ly/example`  
  *URL shortener (potential redirect)*

- `http://example.com:8080/secure`  
  *Unusual port number*

- `http://newlyregistereddomain.com`  
  *Newly registered domain (if available)*




### Limitations of the Tool
- **No External APIs**: To keep the tool simple and self-contained, it does not use external APIs like VirusTotal or Google Safe Browsing for checking against real-time blacklists.
- **Risk of False Positives/Negatives**: Since the detection logic is based on a set of hardcoded rules, there is a chance of both false positives (flagging a safe site as malicious) and false negatives (missing a real phishing site). Results should be used cautiously.
- **Sophisticated Attacks**: It may not flag phishing pages hosted on legitimate but compromised domains.
- **No Content Analysis**: The scanner only analyzes the URL, not the content of the webpage itself.
- **URL Shorteners**: It cannot expand shortened URLs (like from bit.ly) to see the final destination.

### Skills Learned
- **Python Scripting**: Enhanced my skills in writing modular and object-oriented Python code.
- **Cybersecurity Fundamentals**: Gained practical experience in identifying the technical indicators of phishing attacks.
- **Algorithmic Thinking**: Developed a systematic approach to breaking down a complex problem (phishing detection) into a series of logical checks.

### Key Takeaway
My main takeaway from this task is that I was able to gain a deep, practical understanding of how phishing attacks are constructed within weblinks. By building a tool to detect them, I learned to identify the subtle and overt characteristics attackers use to deceive users, from manipulating subdomains and using suspicious keywords to leveraging typosquatting. This hands-on experience was invaluable in learning how to spot and analyze these threats effectively.

</details>

<details>
<summary><h2>Task 2: Password Strength Scanner using Python</h2></summary>

### Tool Overview
The Password Strength Checker is a command-line tool written in Python that analyzes a password's security based on the latest NIST 800-63B v2.0 guidelines. It goes beyond simple character checks by evaluating password length, uniqueness, predictability, and whether it has been exposed in known data breaches. The tool provides a final strength score and actionable feedback to help users create more secure passwords.

### How to Run the Tool
### Prerequisites:
- Python 3: Ensure you have Python 3 installed.

- Requests Library: The tool uses the requests library to download password lists and check for breaches.

### Steps:
- Download the Code: Save the Python script as password_checker.py.

- Open a Terminal: Open your command prompt or terminal.

- Navigate to the Directory: Use the cd command to navigate to the folder where you saved password_checker.py.

- Install Dependencies: Run the following command to install the necessary library:

```
pip install requests
```

- Run the Script: Execute the script using the Python interpreter:

```
python password_checker.py
```

- Enter a Password: The tool will prompt you to enter a password for analysis.

### What is NIST 800-63B? 📜
- The NIST (National Institute of Standards and Technology) Special Publication 800-63B provides guidelines for digital identity, including password policies for government agencies and other organizations. It represents a modern approach to password security, emphasizing factors that are proven to be effective:

  - Length over Complexity: A longer password is significantly harder to crack than a short, complex one.

  - Checking Against Breached Lists: Passwords found in data breaches are instantly insecure, no matter how complex they are.

  - Avoiding Predictable Patterns: Common words, sequences, and keyboard patterns make passwords weak.

- This tool is built to reflect these modern, evidence-based standards.

### How Does This Tool Help?
- This checker acts as an automated security consultant 🕵️. It gives you immediate, clear feedback on your password choices, helping you understand why a password is weak or strong. By using it, you can make informed decisions to protect your accounts from brute-force attacks and credential stuffing.

### Tips for Strong Passwords 🛡️
- Length is Your Best Friend: Aim for a minimum of 14 characters. A passphrase (a sequence of random words like correct horse battery staple) is a great way to achieve this.

- Be Unique for Every Account: Never reuse passwords across different websites. If one site is breached, all your accounts with that password become vulnerable.

- Avoid Predictable Information: Don't use your name, birthday, pet's name, or other easily guessable information.

- Use a Password Manager: The best way to manage strong, unique passwords for all your accounts is with a password manager. It can generate and store them securely for you.

### Checks Used in the Checker
- Breached Password Check: Uses the Have I Been Pwned API to see if your password has appeared in any known data breaches. This is done securely using a k-Anonymity model, so your full password is never sent.

- Common Password Check: The tool downloads and checks against lists of the most common and weakest passwords (from SecLists) to ensure you're not using one of them.

- Length Analysis: Scores the password heavily based on its length, rewarding longer passwords with significantly more points.

- Character Variety: Checks for a mix of uppercase letters, lowercase letters, numbers, and symbols.

- Entropy Calculation: Measures the password's unpredictability. Higher entropy means it's more resistant to guessing attacks.

- Bad Pattern Detection: Penalizes the score for common weaknesses like:

  - Repeated characters (e.g., aaaaaa, 1111)

  - Sequential characters (e.g., abcdef, 12345)

  - Keyboard patterns (e.g., qwerty, asdfgh)

### Limitations of the Tool
- API Dependency: The breach check relies on the Have I Been Pwned API. If the service is down or your internet connection fails, this check will be skipped.

- Offline Lists: The common password lists are downloaded from GitHub. While comprehensive, they may not be updated in real-time with newly discovered weak passwords.

- Not a Complete Security Solution: A strong password is just one part of security. It does not protect you from malware, phishing attacks, or compromised websites. Always enable two-factor authentication (2FA) where possible.

### Skills Learned
- Python Scripting: Writing an interactive command-line application and using standard libraries like hashlib, re, json, and os.

- API Integration: Interacting with a public, security-focused API (HaveIBeenPwned) and handling responses.

- Cybersecurity Fundamentals: Gaining a practical understanding of password hashing (SHA-1), entropy, k-Anonymity, and the principles behind modern password standards (NIST 800-63B).

- Data Handling: Caching data locally in a JSON file to improve performance and reduce network requests.

### Key Takeaway
- My biggest takeaway is that length and uniqueness are far more important than outdated complexity rules. I also saw just how dangerous password reuse is, making data breach checks an absolutely essential part of staying secure. This project was a great hands-on way to apply current security guidelines to create a tool that offers practical, effective advice.

</details>
