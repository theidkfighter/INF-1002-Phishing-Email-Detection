# Test

def ThreadExecutor():
    pass
def classify_email(email_features):

    score = 0

    if not email_features['is_whitelisted']:
        score += 2

    score += 2*email_features['suspicious_keywords']

    if email_features['keyword_in_subject']:
        score += 3
    elif email_features['keyword_in_body']:
        score += 1


    if email_features['similar-domain']:
        score += 3

    threshold = 7
    if score >= threshold:
        return "Phishing", score
    else:
        return "Safe", score 