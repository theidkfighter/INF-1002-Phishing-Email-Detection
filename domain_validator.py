
import re
from typing import Optional

from config import EMAIL_REGEX, DOMAIN_REGEX
from models import ValidationResult

class DomainValidator:
    
    def __init__(self, trusted_domains: list):
        self.trusted_domains = trusted_domains
    
    def extract_domain_from_email(self, email: str) -> Optional[str]:
        
        '''
        Objective is to retrieve VALID senders' email domains through several rigorous validations
        '''
        
        if not email or not isinstance(email, str):
            return None
        
        # Checks basic email format
        if '@' not in email:
            return None
        
        try:
            local_part, domain_part = email.split('@')
            domain_part = domain_part.lower().strip()
            
            # Additional validation checks
            if not local_part or not domain_part:
                return None
                
            if '.' not in domain_part:
                return None
                
            if domain_part.startswith('.') or domain_part.endswith('.'):
                return None
                
            if '..' in domain_part:
                return None
                
            # Regex validation
            if not re.match(EMAIL_REGEX, email):
                return None
    
            return domain_part
            
        except Exception as e:
            return None
    
    # Email Validation
    def validate_email(self, email: str) -> ValidationResult:
        
        '''
        Validates the email address if it is a SAFE or PHISHING email
        
        Otherwise, it will be deemed as an invalid email address
        '''
        
        domain = self.extract_domain_from_email(email)
        
        if not domain:
            return ValidationResult(
                email=email,
                domain=None,
                is_trusted=False,
                message="Invalid email format or domain"
            )
        
        # Additional domain format validation
        if not re.match(DOMAIN_REGEX, domain):
            return ValidationResult(
                email=email,
                domain=None,
                is_trusted=False,
                message="Invalid domain format"
            )
        
        # Validates domain against the whitelist
        is_trusted = domain in self.trusted_domains
        
        return ValidationResult(
            email=email,
            domain=domain,
            is_trusted=is_trusted,
            message="SAFE email domain." if is_trusted 
                   else "PHISHING email domain."
        )
    
    # Domain Validation
    def validate_domain(self, domain: str) -> ValidationResult:
        
        '''
        Validates the email domain if it is a SAFE or PHISHING email
        
        Otherwise, it will be deemed as an invalid email domain
        '''
        
        domain_lower = domain.lower().strip()

        if not re.match(DOMAIN_REGEX, domain_lower):
            return ValidationResult(
                email=f"user@{domain_lower}",
                domain=None,
                is_trusted=False,
                message="Invalid domain format"
            )
        
        # Validates the domain against the whitelist
        is_trusted = domain_lower in self.trusted_domains
        
        return ValidationResult(
            email=f"user@{domain_lower}",
            domain=domain_lower,
            is_trusted=is_trusted,
            message="SAFE domain." if is_trusted 
                   else "PHISHING domain."
        )
