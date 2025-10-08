
import csv
import re
import io
import traceback
from typing import List, Optional, Dict
from domain_validator import DomainValidator
from susUrlDetect import susUrlDetect
from detect_email_keyword import analyze_email_keywords
from editDistanceCheck import editDistanceCheck

class CSVProcessor:
    
    @staticmethod
    def extract_headers(file_stream) -> List[str]:
        
        '''
        Extracts all of the headers in the first row of the CSV file

        Stores it as a list to be used in the subsequent functions
        '''

        try:
            file_stream.seek(0)
            content = file_stream.read().decode('utf-8')
            file_stream.seek(0)
            
            first_line = content.split('\n')[0].strip()
            
            if ',' in first_line:
                headers = first_line.split(',')
            elif '\t' in first_line:
                headers = first_line.split('\t')
            else:
                headers = [first_line]
                
            return [header.strip() for header in headers if header.strip()]
        except Exception as e:
            raise ValueError(f"Error extracting headers: {str(e)}")
    
    @staticmethod
    def detect_sender_column(headers: List[str]) -> Optional[int]:
        
        """
        Identify the sender emails column based on possible keywords used to name its corresponding header
        """

        if not headers:
            return None
            
        sender_keywords = ['sender', 'from', 'source', 'origin', 'email', 'mail', 'address']
        
        for i, header in enumerate(headers):
            header_lower = header.lower()
            if any(keyword in header_lower for keyword in sender_keywords):
                return i
        
        return None
    
    @staticmethod
    def detect_body_column(headers: List[str]) -> Optional[int]:
        
        """
        Identify the email body column based on possible keywords used to name its corresponding header
        """

        if not headers:
            return None
            
        body_keywords = ['body', 'content', 'message', 'text', 'email_body', 'description']
        
        for i, header in enumerate(headers):
            header_lower = header.lower()
            if any(keyword in header_lower for keyword in body_keywords):
                return i
        
        return None
    
    # Extracts potential email addresses from text
    @staticmethod
    def extract_potential_emails_from_text(text: str) -> List[str]:

        if not text:
            return []
        
        # A more rigorous validation that uses regex that catches email-like patterns
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\b')
        return email_pattern.findall(text)
    
    @staticmethod
    def is_valid_email_format(email: str) -> bool:
        
        """
        Ensures the extracted emails have the valid format

        E.g. email contains '@' or '.'
        """

        if not email or '@' not in email:
            return False
        
        try:
            local_part, domain_part = email.split('@')
            # Check basic requirements
            if (not local_part or not domain_part or 
                '.' not in domain_part or 
                domain_part.startswith('.') or 
                domain_part.endswith('.') or
                '..' in domain_part or
                len(domain_part.split('.')[-1]) < 2):  # TLD should be at least 2 chars
                return False
            return True
        except:
            return False
    
    @staticmethod
    def extract_email_from_sender_field(sender_text: str) -> Optional[str]:
        
        """
        Extracts emails from sender field which may contain name and email
        """

        if not sender_text:
            return None
        
        # Looks for email in angle brackets
        bracket_pattern = re.compile(r'<([^>]+@[^>]+)>')
        bracket_match = bracket_pattern.search(sender_text)
        if bracket_match:
            return bracket_match.group(1)
        
        # If no brackets, proceeds to extract potential emails
        potential_emails = CSVProcessor.extract_potential_emails_from_text(sender_text)
        if potential_emails:
            return potential_emails[0]
        
        return None
    
    @staticmethod
    def process_csv_file(file_stream, domain_validator: DomainValidator, trusted_domains: List[str]) -> List[Dict]:
        
        """
        Process CSV file content

        Returns:
        - ONE result per row
        - Only looks for sender emails in the sender column
        - Invalid email domains and rows with no senders' emails are accounted for and will not proceed with the remaining email validation
        """

        try:
            file_stream.seek(0)
            content = file_stream.read().decode('utf-8')
            
            # Parse CSV using Python's CSV reader
            csv_reader = csv.reader(io.StringIO(content))
            rows = list(csv_reader)
            
            if not rows:
                return []
            
            headers = [header.strip() for header in rows[0] if header.strip()]
            
            # Detect columns
            sender_col = CSVProcessor.detect_sender_column(headers)
            body_col = CSVProcessor.detect_body_column(headers)
            
            
            # If no sender column detected, first column is used as default
            if sender_col is None:
                sender_col = 0
            
            results = []
            
            # Processes data rows (skip header)
            for i, row in enumerate(rows[1:], start=1):
                
                # Skips empty rows
                if not row or not any(cell.strip() for cell in row):
                    continue
                
                cells = [cell.strip() for cell in row]
                
                # Finds email address - Only search in sender column
                sender_email = None
                potential_email_found = False
                invalid_email_candidate = None
                
                # Checks if sender column exists in this row
                if sender_col < len(cells) and cells[sender_col]:
                    sender_cell = cells[sender_col]
                    
                    # Extracts email from sender field
                    potential_email = CSVProcessor.extract_email_from_sender_field(sender_cell)
                    
                    if potential_email:
                        potential_email_found = True
                        invalid_email_candidate = potential_email
                        
                        # Check if email format is valid
                        if CSVProcessor.is_valid_email_format(potential_email):
                            sender_email = potential_email
                
                # Validations are skipped if no email is found in the sender column
                if not potential_email_found:

                    results.append({
                        "row_number": i,
                        "email": "N/A",
                        "domain": None,
                        "risk_level": "NO EMAIL FOUND",
                        "is_trusted": False,
                        "is_invalid": True,
                        "edit_distance_message": "Validation skipped - no email",
                        "url_detection_messages": [],
                        "keyword_risk_rating": "N/A",
                        "flagged_keywords": [],
                        "risk_index": 0,
                        "validation_notes": "No email address found in sender column"
                    })
                    continue
                
                # Validations are skipped if email has an invalid format (e.g. user@gmail without the '.com')
                if not sender_email and potential_email_found:
    
                    results.append({
                        "row_number": i,
                        "email": invalid_email_candidate,
                        "domain": None,
                        "risk_level": "INVALID DOMAIN",
                        "is_trusted": False,
                        "is_invalid": True,
                        "edit_distance_message": "Validation skipped - invalid email format",
                        "url_detection_messages": [],
                        "keyword_risk_rating": "N/A",
                        "flagged_keywords": [],
                        "risk_index": 0,
                        "validation_notes": f"Invalid email format in sender column: {invalid_email_candidate}"
                    })
                    continue
                
                # Domain validation
                domain_result = domain_validator.validate_email(sender_email)
                
                # If domain validation fails, remaining validations are skipped
                if domain_result.domain is None:
                    print(f"❌ DEBUG: Row {i} - DOMAIN VALIDATION FAILED: {sender_email}")
                    results.append({
                        "row_number": i,
                        "email": sender_email,
                        "domain": None,
                        "risk_level": "INVALID DOMAIN",
                        "is_trusted": False,
                        "is_invalid": True,
                        "edit_distance_message": "Validation skipped - domain validation failed",
                        "url_detection_messages": [],
                        "keyword_risk_rating": "N/A",
                        "flagged_keywords": [],
                        "risk_index": 0,
                        "validation_notes": f"Domain validation failed: {domain_result.message}"
                    })
                    continue
                
                # Extracts email body from body column if available, otherwise use other columns
                email_body = ""
                if body_col is not None and body_col < len(cells) and cells[body_col]:
                    email_body = cells[body_col]
                else:
                    # Find longest text field as body, excluding the sender column
                    for j, cell in enumerate(cells):
                        if j != sender_col and cell and len(cell) > len(email_body):
                            email_body = cell
                
                # Run full validation
                edit_distance_result = editDistanceCheck(sender_email, trusted_domains)

                url_result = susUrlDetect(email_body)

                keyword_result = analyze_email_keywords(email_body, "")
                
                # Calculates final score index
                risk_index = 0
                if not domain_result.is_trusted:
                    risk_index += 1
                risk_index += edit_distance_result["riskScore"]
                risk_index += url_result["riskScore"]
                risk_index += keyword_result["riskScore"]
                
                risk_level = "SAFE" if risk_index == 0 else "PHISHING"
                
                results.append({
                    "row_number": i,
                    "email": sender_email,
                    "domain": domain_result.domain,
                    "risk_level": risk_level,
                    "is_trusted": domain_result.is_trusted,
                    "is_invalid": False,
                    "edit_distance_message": edit_distance_result["message"],
                    "url_detection_messages": url_result["riskMsg"],
                    "keyword_risk_rating": keyword_result["risk_rating"],
                    "flagged_keywords": keyword_result["flagged_word"],
                    "risk_index": risk_index,
                    "validation_notes": "Full validation completed"
                })
            
            # Detailed breakdown
            safe_count = len([r for r in results if r["risk_level"] == "SAFE"])
            phishing_count = len([r for r in results if r["risk_level"] == "PHISHING"])
            invalid_domain_count = len([r for r in results if r["risk_level"] == "INVALID DOMAIN"])
            no_email_count = len([r for r in results if r["risk_level"] == "NO EMAIL FOUND"])
            total_invalid = len([r for r in results if r["is_invalid"]])
            
            print(f"📈 DEBUG: Safe emails: {safe_count}")
            print(f"📈 DEBUG: Phishing emails: {phishing_count}")
            print(f"📈 DEBUG: Invalid domains: {invalid_domain_count}") 
            print(f"📈 DEBUG: No email rows: {no_email_count}")
            print(f"📈 DEBUG: Total invalid (all types): {total_invalid}")
            print(f"📈 DEBUG: Sum check: {safe_count + phishing_count + invalid_domain_count + no_email_count} = {len(results)}")
            
            return results
            
        except Exception as e:
            print(f"💥 DEBUG: Error in CSV processing: {str(e)}")
            traceback.print_exc()
            raise ValueError(f"Error processing CSV file: {str(e)}")
