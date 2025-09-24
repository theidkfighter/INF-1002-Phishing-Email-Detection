
from typing import List
from config import TRUSTED_DOMAINS_FILE, DEFAULT_TRUSTED_DOMAINS

class DomainManager:
    
    @staticmethod
    def load_trusted_domains() -> List[str]:
        
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
    
    @staticmethod
    def add_trusted_domain(domain: str) -> bool:

        try:
            with open(TRUSTED_DOMAINS_FILE, 'a') as file:
                file.write(f"\n{domain.lower()}")
            return True
        except Exception as e:
            print(f"Error adding domain: {str(e)}")
            return False
    
    @staticmethod
    def remove_trusted_domain(domain: str) -> bool:
        
        try:
            
            with open(TRUSTED_DOMAINS_FILE, 'r') as file:
                domains = file.readlines()
            
            
            domain_lower = domain.lower()
            filtered_domains = [
                line for line in domains 
                if line.strip().lower() != domain_lower
            ]
            
            
            with open(TRUSTED_DOMAINS_FILE, 'w') as file:
                file.writelines(filtered_domains)
            
            return True
        except Exception as e:
            print(f"Error removing domain: {str(e)}")
            return False
