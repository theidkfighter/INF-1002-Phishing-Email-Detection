<div align="center">
  <h1>PHISHGUARD</h1>
  <p>
    Python Project for INF1002 Programming Fundamentals.
  </p>
</div>

## About

PhishGuard is a web-based phishing email detection program mainly developed in Python. In our program, users can either paste the email content from a Single Email or upload a CSV of emails. The output is the email validation result in which it determines if the email is considered as 'Safe' or 'Phishing' based on a generated Final Risk Score.

Our program features include:
1. **Whitelist Check** - Checks if the sender's email address is on a predefined whitelist.

2. **Keyword Detection** - Scans the email subject and body for suspicious keywords.

3. **Keyword Position Scoring** - Assigns a score to each suspicious keyword identified.

4. **Edit Distance Check** - Compares email domains and sender names against known authentic domains to identify aesthetically similar fakes.

5. **Suspicious URL Detection** - Identifies links that do not correspond to the claimed domain or contain IP addresses instead of domains.

6. **Final Risk Scoring** - Calculates the results from all the rules to classify the emails as 'Safe' or 'Phishing'.

## Getting Started

### Installation

**With Python & pip**

```bash
pip install flask
pip install tldextract
```

### Execution

**Run the program**

```bash
python app.py
```

## PHISHGUARD TESTCASES
**Test Case 1**: Single Domain Validation with a valid Safe email domain and body content

Email (mandatory): user@gmail.com\
Subject Title (optional): Hello World\
Email Body (mandatory): Beautiful skies

Expected Output: SAFE domain with the Risk Level reflected as "LOW" and Detection Details displayed.

**Test Case 2**: Single Domain Validation with an invalid email

Email (mandatory): user@gmail\
Subject Title (optional): Hello World\
Email Body (mandatory): Beautiful skies

Expected Output: INVALID domain and 'N/A' is displayed for both Risk Level and Detection Details.

**Test Case 3**: Single Domain Validation with a valid Phishing email domain but a Safe body content

Email (mandatory): user@outloook.com\
Subject Title (Optional):\
Email Body (mandatory): Hello World

Expected Output: PHISHING domain with the Risk Level reflected as "MEDIUM" and Detection Details displayed.

**Test Case 4**: Single Domain Validation with a valid Safe email domain but a Phishing body content

Email (mandatory): user@outlook.com\
Subject Title (Optional):\
Email Body (mandatory): Click on this link to earn free money: https://172.169.152.10:80/

Expected Output: SAFE domain with the Risk Level reflected as "MEDIUM" and Detection Details displayed.

**Test Case 5**: Single Domain Validation with a valid Phishing email domain and body content

Email (mandatory): user@gmmail.com\
Subject Title (Optional):\
Email Body (mandatory): Click on this link to earn free money: https://172.169.152.10:80/

Expected Output: PHISHING domain with Risk Level reflected as "HIGH" and Detection Details displayed.

**Test Case 6**: CSV File Validation

Upload "Nigerian Small" CSV file.

Expected Output: Display a list of the validation result from the CSV file content; Rows with invalid or no email addresses are ignored (meaning no further validation is carried out on these rows).

An option for users to download the CSV Validation Result file to view the report details per row.
