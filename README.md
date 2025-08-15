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
