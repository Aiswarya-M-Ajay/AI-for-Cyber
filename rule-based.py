import pandas as pd
import re

# Load the dataset
dataset_path = r"C:\Users\HP\OneDrive\Desktop\AI\SpamAssasin.csv"  # Replace with the correct file path
df = pd.read_csv(dataset_path)

# Define a function to fetch emails from the dataset
def fetch_emails_from_dataset(df):
    emails = []
    for index, row in df.iterrows():
        # Fetch email details from the dataset and handle missing values
        sender = str(row.get('sender', ''))  # Convert to string and handle missing values
        subject = str(row.get('subject', ''))
        body = str(row.get('body', ''))
        
        # Extract links and attachments if available
        links = row.get('Links', '')
        if pd.isna(links):
            links = []
        else:
            links = str(links).split(';')  # Convert to string and split
        
        attachments = row.get('Attachments', '')
        if pd.isna(attachments):
            attachments = []
        else:
            attachments = str(attachments).split(';')  # Convert to string and split

        emails.append((sender, subject, body, links, attachments))
    return emails

# Define the phishing detection function with rules
def detect_phishing(sender, subject, body, links, attachments):
    is_phishing = False
    triggered_rules = []

    # Rule 1: Flag emails from suspicious domains (e.g., domains with typos)
    suspicious_domains = ["MN2PR19MB3966.namprd19.prod.outlook.com", "fakebank.com", "sotrecognizd@gmail.com","BN8NAM11FT066.mail.protection.outlook.com ","SA3PR19MB7370.namprd19.prod.outlook.com"]  # Example list
    if any(domain in sender for domain in suspicious_domains):
        triggered_rules.append("Suspicious sender domain")
        is_phishing = True
    
    # Rule 2: Detect the use of urgent language (e.g., "immediate action required")
    urgent_phrases = ["immediate action required", "urgent", "verify your account", "limited time offer"]
    if any(phrase in body.lower() for phrase in urgent_phrases):
        triggered_rules.append("Urgent language")
        is_phishing = True
    
    # Rule 3: Identify URLs that do not match the legitimate domain of the sender
    legitimate_domain = "legitbank.com"  # Replace with legitimate domain
    if links and any(legitimate_domain not in link for link in links):
        triggered_rules.append("Mismatched URLs")
        is_phishing = True
    
    # Rule 4: Check for attachments with potentially malicious file types (e.g., .exe, .zip)
    dangerous_extensions = [".exe", ".zip", ".scr", ".js"]
    if attachments and any(attachment.lower().endswith(tuple(dangerous_extensions)) for attachment in attachments):
        triggered_rules.append("Malicious attachment")
        is_phishing = True
    
    # Rule 5: Identify poorly written emails with frequent grammatical errors
    if check_grammar_errors(body):
        triggered_rules.append("Poor grammar")
        is_phishing = True

    if is_phishing:
        result = "Phishing Email"
    else:
        result = "Legitimate Email"

    return result, triggered_rules

# Function to check for grammar errors (basic placeholder function)
def check_grammar_errors(text):
    grammar_issues = ["greeting from", "congratulation", "lottery win"]
    return any(issue in text.lower() for issue in grammar_issues)

# Function to read email from a file
def read_email_from_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    # For simplicity, let's assume the content is structured in a specific way:
    # First line: sender, Second line: subject, Remaining lines: body
    lines = content.splitlines()
    sender = lines[0] if len(lines) > 0 else ''
    subject = lines[1] if len(lines) > 1 else ''
    body = "\n".join(lines[2:]) if len(lines) > 2 else ''
    return sender, subject, body

# Fetch emails from the dataset
emails = fetch_emails_from_dataset(df)

# Analyze each email and print results
for email in emails:
    result, triggered_rules = detect_phishing(*email)
    print("Email Analysis Result:", result)
    if triggered_rules:
        print("Rules Triggered:", ", ".join(triggered_rules))
    else:
        print("Rules Triggered: None")

# Test with specific phishing and legitimate emails
def test_email(file_path):
    sender, subject, body = read_email_from_file(file_path)
    result, triggered_rules = detect_phishing(sender, subject, body, [], [])
    print("\nTest Email Path:", file_path)
    print("Test Result:", result)
    if triggered_rules:
        print("Rules Triggered:", ", ".join(triggered_rules))
    else:
        print("Rules Triggered: None")

# Paths to the phishing and legitimate email files
legitimate_email_path = r"C:\Users\HP\OneDrive\Desktop\AI\sample2.eml" 
legitimate_email_path = r"C:\Users\HP\OneDrive\Desktop\AI\sample7.eml" # Replace with the correct path
phishing_email_path = r"C:\Users\HP\OneDrive\Desktop\AI\sample-10.eml"
phishing_email_path = r"C:\Users\HP\OneDrive\Desktop\AI\sample-100.eml"
phishing_email_path = r"C:\Users\HP\OneDrive\Desktop\AI\sample-1.eml"  # Replace with the correct path

# Test and print results for specific emails
test_email(legitimate_email_path)
test_email(phishing_email_path)
