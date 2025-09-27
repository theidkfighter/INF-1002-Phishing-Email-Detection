
from flask import Flask, request, jsonify, render_template
import traceback

from config import MAX_FILE_SIZE
from domain_manager import DomainManager
from domain_validator import DomainValidator
from file_processor import CSVProcessor
from susUrlDetect import susUrlDetect
from final_score import FinalScoreCalculator

app = Flask(__name__)

app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

trusted_domains = DomainManager.load_trusted_domains()
domain_validator = DomainValidator(trusted_domains)
csv_processor = CSVProcessor()
scorer = FinalScoreCalculator()

@app.route('/')
def index():
    return render_template('index.html')

# Validates single or multiple senders' email domains
#THIS WHERE YOU WILL BE ADDING IN YOUR FUNCTIONS -ZQ
@app.route('/validate', methods=['POST']) #THIS IS WHERE THE CODE WILL RUN AFTER THE USER PRESS THE BUTTON WITH VALID INPUTS/ VALID CSV FILES
def validate():

    try:
        
        if 'csv_file' in request.files: #THIS PART IS FOR CSV FILES AND YOU CAN EDIT BY ADDING YOUR FUNCTIONS AND TRY TO FIT INTO THE RESULTS DICT BELOW
            file = request.files['csv_file']
            if file and file.filename != '':
                file.seek(0, 2)
                file_size = file.tell()
                file.seek(0)
                
                if file_size > MAX_FILE_SIZE: #CHECK FILESIZE
                    return jsonify({"error": f"File too big. Maximum size is {MAX_FILE_SIZE//(1024*1024)}MB."}), 400
                
                if not file.filename.lower().endswith('.csv'): #CHECK IF IT IS CSV
                    return jsonify({"error": "Not a CSV file"}), 400
                
                try:
                    
                    results = csv_processor.process_csv_file(file, domain_validator)
                    trusted_count = sum(1 for r in results if r.is_trusted)
                    phishing_count = len(results) - trusted_count
                    
                    return jsonify({
                        "results": [result.__dict__ for result in results], 
                        "type": "csv",
                        "row_count": len(results),
                        "trusted_count": trusted_count,
                        "phishing_count": phishing_count
                    })
                except Exception as e:
                    app.logger.error(f"Error processing CSV: {str(e)}")
                    app.logger.error(traceback.format_exc())
                    return jsonify({"error": f"Error processing CSV file: {str(e)}"}), 400 #IF THERE IS ERROR PROCESSING CSV
        
        # THIS PART IS IF USER USES THE SINGLE INPUT OF EMAIL ADDRESS AND EMAIL BODY
        domain_input = request.form.get('domain', '').strip()
        email_bodyInput = request.form.get('emailBody', '').strip()
        if not domain_input or not email_bodyInput:
            return jsonify({"error": "No domain or email body provided"}), 400 #ABIT REDUNDANT AND MAY CHANGE BUT THIS IS CHECK IF THERE IS VALID INPUT
        
        # Determine if input is email or domain
        if '@' in domain_input:
            result = domain_validator.validate_email(domain_input)
        else:
            result = domain_validator.validate_domain(domain_input)
        
        email_bodyRiskMsg = susUrlDetect(email_bodyInput) # THIS IS MY SUS URL DETECT FOR BODY RISK MSG BUT YOU MAY CHANGE TO YOUR CODE TO TRY IT OUT AND SEE IF IT WILL PRINT IN THE WEB
        
        from final_score import FinalScoreCalculator
        scorer = FinalScoreCalculator()
        scoring_result = scorer.score(
            sender_email=domain_input,
            subject="",  # can extend later if you capture subject
            body=email_bodyInput,
            links=[]     # or parse links if needed
        )

        # Build result dictionary
        result_dict = {
            "email": result.email,
            "domain": result.domain,
            "is_trusted": result.is_trusted,
            "message": result.message,
            "bodyRiskMsg": email_bodyRiskMsg,
            "final_score": scoring_result["score"],
            "label": scoring_result["label"],
            "risk_level": scoring_result["risk_level"],
            "details": scoring_result["details"]
        }


        print("DEBUG RESULT:", result_dict)
        
        return jsonify({
            "results": [result_dict], 
            "type": "single",
            "row_count": 1,
            "trusted_count": 1 if result.is_trusted else 0,
            "phishing_count": 0 if result.is_trusted else 1
        })
    
    except Exception as e:
        app.logger.error(f"Error encountered in validate endpoint: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({"Error encountered"}), 500

# Extracts headers from CSV file
@app.route('/get_headers', methods=['POST'])
def get_headers():
    
    try:
        if 'csv_file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
            
        file = request.files['csv_file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({"error": f"File too big. Maximum size is {MAX_FILE_SIZE//(1024*1024)}MB."}), 400
        
        if not file.filename.lower().endswith('.csv'):
            return jsonify({"error": "Not a CSV file"}), 400
        
        headers = csv_processor.extract_headers(file.stream)
        
        return jsonify({"headers": headers})
            
    except Exception as e:
        app.logger.error(f"Error extracting headers: {str(e)}")
        return jsonify({"error": f"Error extracting headers: {str(e)}"}), 500

# Retrieves the predefined whitelist of email domains
@app.route('/domains', methods=['GET'])
def get_domains():
    
    try:
        return jsonify({"domains": trusted_domains})
    except Exception as e:
        app.logger.error(f"Error in get_domains: {str(e)}")
        return jsonify({"error": "Failed to load domains"}), 500

# @app.route('/domains', methods=['POST'])
# def add_domain():

#     try:
#         domain = request.json.get('domain', '').strip()
        
#         if not domain:
#             return jsonify({"error": "No domain provided"}), 400
        
#         success = DomainManager.add_trusted_domain(domain)
        
#         if success:
#             trusted_domains.append(domain.lower())
#             return jsonify({"message": "Domain added successfully"})
#         else:
#             return jsonify({"error": "Failed to add domain"}), 500
#     except Exception as e:
#         app.logger.error(f"Error in add_domain: {str(e)}")
#         return jsonify({"error": "An unexpected error occurred"}), 500

# @app.route('/domains/<domain>', methods=['DELETE'])
# def remove_domain(domain):

#     try:
#         success = DomainManager.remove_trusted_domain(domain)
        
#         if success:
#             domain_lower = domain.lower()
#             if domain_lower in trusted_domains:
#                 trusted_domains.remove(domain_lower)
#             return jsonify({"message": "Domain removed successfully"})
#         else:
#             return jsonify({"error": "Failed to remove domain"}), 500
#     except Exception as e:
#         app.logger.error(f"Error in remove_domain: {str(e)}")
#         return jsonify({"error": "An unexpected error occurred"}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": f"File too big. Maximum size is {MAX_FILE_SIZE//(1024*1024)}MB."}), 413

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=8000)