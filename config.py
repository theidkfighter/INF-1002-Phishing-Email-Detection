
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Path to trustable_email_domains.txt file
TRUSTED_DOMAINS_FILE = os.path.join(BASE_DIR, 'trustable_email_domains.txt')

# Fallback domains if provided whitelist file cannot be read
DEFAULT_TRUSTED_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "icloud.com", "protonmail.com", "zoho.com", "mail.com", "gmx.com"
]

# Validation settings
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
DOMAIN_REGEX = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'

# CSV file processing limits
MAX_FILE_SIZE = 50 * 1024 * 1024
CHUNK_SIZE = 1000