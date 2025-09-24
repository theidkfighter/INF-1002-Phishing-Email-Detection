
import csv
import re
from typing import List, Optional

from models import ValidationResult
from domain_validator import DomainValidator

class CSVProcessor:
    
    @staticmethod
    def extract_headers(file_stream) -> List[str]:
        
        try:
            
            line = file_stream.readline().decode('utf-8')
            file_stream.seek(0)
            
            
            try:
                
                if '\t' in line:
                    headers = next(csv.reader([line], delimiter='\t'))
                else:
                    headers = next(csv.reader([line]))
                return [header.strip() for header in headers if header.strip()]
            except:
                # If CSV parsing fails, resort to simple comma or tab separation
                if '\t' in line:
                    headers = line.strip().split('\t')
                else:
                    headers = line.strip().split(',')
                return [header.strip() for header in headers if header.strip()]
        except Exception as e:
            raise ValueError(f"Error extracting headers: {str(e)}")
    
    # Identify list of senders' email domains
    @staticmethod
    def detect_sender_column(headers: List[str]) -> Optional[int]:
        
        sender_keywords = ['sender', 'from', 'source', 'origin', 'email', 'mail']
        
        for i, header in enumerate(headers):
            header_lower = header.lower()
            if any(keyword in header_lower for keyword in sender_keywords):
                return i
        
        # If no specific sender column found, check if any column might contain emails
        for i, header in enumerate(headers):
            if any(keyword in header.lower() for keyword in ['address', 'contact', 'user']):
                return i
        
        return None
    
    @staticmethod
    def extract_emails_from_text(text: str) -> List[str]:
        
        email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
        return email_pattern.findall(text)
    
    @staticmethod
    def process_csv_file(file_stream, domain_validator: DomainValidator) -> List[ValidationResult]:
        
        try:
    
            content = file_stream.read().decode('utf-8')
            lines = content.split('\n')
            
            results = []
            
            # Detects headers and sender column
            headers = None
            sender_column_index = None
            
            if lines and lines[0].strip():
                first_line = lines[0].strip()
                if '\t' in first_line:
                    headers = first_line.split('\t')
                else:
                    headers = first_line.split(',')
                
                headers = [header.strip() for header in headers if header.strip()]
                sender_column_index = CSVProcessor.detect_sender_column(headers)
            
            start_line = 1 if headers else 0  # Skips header row if headers exist
            
            for i in range(start_line, len(lines)):
                line = lines[i].strip()
                if not line:
                    continue
                
                if '\t' in line:
                    cells = line.split('\t')
                else:
                    cells = line.split(',')
                
                cells = [cell.strip() for cell in cells]
                
                sender_email = None
                
                # Try detected sender column first
                if sender_column_index is not None and sender_column_index < len(cells):
                    email_candidates = CSVProcessor.extract_emails_from_text(cells[sender_column_index])
                    if email_candidates:
                        sender_email = email_candidates[0]
                
                # If no sender column detected or no email found, try all columns
                if not sender_email:
                    for cell in cells:
                        email_candidates = CSVProcessor.extract_emails_from_text(cell)
                        if email_candidates:
                            sender_email = email_candidates[0]
                            break
                
                # If still no email found, search the whole line
                if not sender_email:
                    email_candidates = CSVProcessor.extract_emails_from_text(line)
                    if email_candidates:
                        sender_email = email_candidates[0]
                
                # Validates the sender email if found
                if sender_email:
                    validation_result = domain_validator.validate_email(sender_email)
                    validation_result.original_data = {"line": line}
                    results.append(validation_result)
            
            return results
        except Exception as e:
            raise ValueError(f"Error processing CSV file: {str(e)}")
    
    @staticmethod
    def process_csv_file_with_headers(file_stream, domain_validator: DomainValidator) -> List[ValidationResult]:

        try:
            
            content = file_stream.read().decode('utf-8')
            lines = content.split('\n')
            
            if not lines:
                return []
            
            
            first_line = lines[0].strip()
            if '\t' in first_line:
                headers = first_line.split('\t')
            else:
                headers = first_line.split(',')
            
            headers = [header.strip() for header in headers if header.strip()]
            
            # Detects sender column
            sender_column_index = CSVProcessor.detect_sender_column(headers)
            
            results = []
            
            # Process each data line (skip header)
            for i in range(1, len(lines)):
                line = lines[i].strip()
                if not line:
                    continue
                
                if '\t' in line:
                    values = line.split('\t')
                else:
                    values = line.split(',')
                
                values = [value.strip() for value in values]
                
                sender_email = None
                
                # Try detected sender column first
                if sender_column_index is not None and sender_column_index < len(values):
                    email_candidates = CSVProcessor.extract_emails_from_text(values[sender_column_index])
                    if email_candidates:
                        sender_email = email_candidates[0]
                
                # If no sender column detected or no email found, try all columns
                if not sender_email:
                    for value in values:
                        email_candidates = CSVProcessor.extract_emails_from_text(value)
                        if email_candidates:
                            sender_email = email_candidates[0]
                            break
                
                # Validates the sender email if found
                if sender_email:
                    validation_result = domain_validator.validate_email(sender_email)
                    validation_result.original_data = {"line": line}
                    results.append(validation_result)
            
            return results
        except Exception as e:
            raise ValueError(f"Error processing CSV file with headers: {str(e)}")
