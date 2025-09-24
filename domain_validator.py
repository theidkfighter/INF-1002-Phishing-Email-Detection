
import re
from typing import Optional

from config import EMAIL_REGEX, DOMAIN_REGEX
from models import ValidationResult

class DomainValidator:
    
    def __init__(self, trusted_domains: list):
        
        self.trusted_domains = trusted_domains
    
    def extract_domain_from_email(self, email: str) -> Optional[str]:
        
        if not re.match(EMAIL_REGEX, email):
            return None
        
        return email.split('@')[1].lower()
    
    # Email Validation
    def validate_email(self, email: str) -> ValidationResult:
        
        domain = self.extract_domain_from_email(email)
        
        if not domain:
            return ValidationResult(
                email=email,
                domain=None,
                is_trusted=False,
                message="Invalid email format"
            )
        
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
        
        domain_lower = domain.lower()

        if not re.match(DOMAIN_REGEX, domain_lower):
            return ValidationResult(
                email=f"user@{domain_lower}",
                domain=None,
                is_trusted=False,
                message="Invalid domain format"
            )
        
        is_trusted = domain_lower in self.trusted_domains
        
        return ValidationResult(
            email=f"user@{domain_lower}",
            domain=domain_lower,
            is_trusted=is_trusted,
            message="SAFE domain." if is_trusted 
                   else "PHISHING domain."
        )
