
from typing import List
from config import TRUSTED_DOMAINS_FILE, DEFAULT_TRUSTED_DOMAINS

class DomainManager:
    
    @staticmethod
    def load_trusted_domains() -> List[str]:
        
        '''
        Reads the list of trustable email domains in the pre-defined whitelisted txt file

        Returns a list of trustable domains
        '''

        try:
            with open(TRUSTED_DOMAINS_FILE, 'r') as file:
                domains = [
                    line.strip().lower() 
                    for line in file 
                    if line.strip() and not line.strip().startswith('#')
                ]
            return domains
        except FileNotFoundError:
            print("trustable_email_domains.txt not found. Using default domains.")
            return DEFAULT_TRUSTED_DOMAINS
