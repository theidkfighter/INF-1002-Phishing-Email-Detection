import re,csv
from typing import Dict, List, Tuple


def analyze_email_keywords(body: str,subject: str = "no header",
                           suspicious_keywords: List[str] = None,
                           subject_weight: float = 2.0,
                           early_body_weight: float = 1.5,
                           base_score: float = 1.0) -> Dict:
    """
    Analyze email for suspicious keywords with position-based scoring.

    Args:
        subject: Email subject line
        body: Email body text
        suspicious_keywords: List of suspicious keywords to detect
        subject_weight: Multiplier for keywords found in subject
        early_body_weight: Multiplier for keywords found in first part of body
        base_score: Base score for each keyword match

    Returns:
        Dictionary containing analysis results
    """

    # Default suspicious keywords
    if suspicious_keywords is None:
        suspicious_keywords = []
        csv.field_size_limit(10000000)
        with open("spam_word_list.csv") as csvfile:
            reader = csv.reader(csvfile)
            for word in reader:
                suspicious_keywords.append(word[0])

    # Preprocess text
    subject_lower = subject.lower()
    body_lower = body.lower()

    # Split body into words for early detection
    body_words = re.findall(r'\b\w+\b', body_lower)
    total_body_words = len(body_words)
    early_threshold = min(50, total_body_words // 4)  # First 50 words or 25% of body

    results = {
        'total_score': 0.0,
        'keyword_matches': [],
        'subject_matches': [],
        'early_body_matches': [],
        'subject_score': 0.0,
        'body_score': 0.0,
        'original_subject': subject,
        'original_body': body,
        'word_count': total_body_words,
        'early_threshold': early_threshold
    }

    # Check subject for keywords
    for keyword in suspicious_keywords:
        # Find all occurrences in subject
        subject_matches = re.findall(rf'\b{re.escape(keyword)}\b', subject_lower)
        if subject_matches:
            score = base_score * subject_weight * len(subject_matches)
            results['subject_score'] += score
            results['total_score'] += score
            results['subject_matches'].extend([{
                'keyword': keyword,
                'count': len(subject_matches),
                'score': score
            }])

    # Check body for keywords with position scoring
    for keyword in suspicious_keywords:
        # Find all occurrences in body
        body_matches = list(re.finditer(rf'\b{re.escape(keyword)}\b', body_lower))

        if body_matches:
            early_matches = 0
            late_matches = 0

            for match in body_matches:
                # Count words before this match to determine position
                text_before = body_lower[:match.start()]
                words_before = len(re.findall(r'\b\w+\b', text_before))

                if words_before < early_threshold:
                    early_matches += 1
                else:
                    late_matches += 1

            # Calculate scores
            early_score = base_score * early_body_weight * early_matches
            late_score = base_score * late_matches

            results['body_score'] += early_score + late_score
            results['total_score'] += early_score + late_score

            if early_matches > 0:
                results['early_body_matches'].append({
                    'keyword': keyword,
                    'count': early_matches,
                    'score': early_score
                })

            if late_matches > 0:
                results['keyword_matches'].append({
                    'keyword': keyword,
                    'count': late_matches,
                    'score': late_score
                })

    outputs = {"flagged_word":[flagged_keyword.get('keyword') for flagged_keyword in results["keyword_matches"]]}
    print(outputs)
    # Add risk assessment
    if results['total_score'] >= 100:
        outputs['risk_rating'] = "high"
    elif results['total_score'] >= 50:
        outputs['risk_rating'] = "medium"
    else:
        outputs['risk_rating'] = "low"

    return outputs


def display_email_content(subject: str, body: str):
    """Display the email content in a formatted way."""
    print("=" * 60)
    print("PHISHING EMAIL CONTENT")
    print("=" * 60)
    print(f"SUBJECT: {subject}")
    print("-" * 60)
    print("BODY:")
    print(body)
    print("=" * 60)
    print()


def highlight_keywords(text: str, keywords: List[str]) -> str:
    """Highlight suspicious keywords in the text."""
    highlighted_text = text
    for keyword in keywords:
        # Use regex to find whole words only (case insensitive)
        pattern = rf'\b{re.escape(keyword)}\b'
        highlighted_text = re.sub(pattern, f'**{keyword.upper()}**', highlighted_text, flags=re.IGNORECASE)
    return highlighted_text




"""# Example usage and test function
def test_keyword_detection():

    with open("TREC_07.csv",encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for email_detail in reader:
            # Analyze the email
            results = analyze_email_keywords(email_detail[3], email_detail[4])

            if results["total_score"] >= 5:
                print(results)
                
                # Display analysis results
                print("EMAIL ANALYSIS RESULTS")
                print("=" * 60)
                print(f"Total Risk Score: {results['total_score']:.2f}")
                print(f"Risk Level: {results['risk_level']}")
                print(f"Subject Score: {results['subject_score']:.2f}")
                print(f"Body Score: {results['body_score']:.2f}")
                print(f"Total Words: {results['word_count']}")
                print(f"Early Threshold (first {results['early_threshold']} words get higher score)")
                print("-" * 60)

                # Display highlighted email content
                all_keywords = [match['keyword'] for match in results['subject_matches'] +
                                results['early_body_matches'] + results['keyword_matches']]
                unique_keywords = list(set(all_keywords))

                print("HIGHLIGHTED CONTENT (suspicious keywords in **CAPS**):")
                print("=" * 60)
                print(f"SUBJECT: {highlight_keywords(results['original_subject'], unique_keywords)}")
                print("-" * 60)
                print("BODY:")
                print(highlight_keywords(results['original_body'], unique_keywords))
                print("=" * 60)

                # Detailed breakdown
                print("\nDETAILED BREAKDOWN:")
                print("=" * 60)

                if results['subject_matches']:
                    print("\nSUBJECT MATCHES (2x multiplier):")
                    for match in results['subject_matches']:
                        print(f"  • {match['keyword']}: {match['count']} match(es), score: {match['score']:.2f}")

                if results['early_body_matches']:
                    print("\nEARLY BODY MATCHES (1.5x multiplier - first {results['early_threshold']} words):")
                    for match in results['early_body_matches']:
                        print(f"  • {match['keyword']}: {match['count']} match(es), score: {match['score']:.2f}")

                if results['keyword_matches']:
                    print("\nOTHER BODY MATCHES (1x multiplier):")
                    for match in results['keyword_matches']:
                        print(f"  • {match['keyword']}: {match['count']} match(es), score: {match['score']:.2f}")

                # Risk explanation
                print("\n" + "=" * 60)
                print("RISK ASSESSMENT EXPLANATION:")
                print(f"Score {results['total_score']:.2f} = ", end="")

                components = []
                if results['subject_score'] > 0:
                    components.append(f"subject({results['subject_score']:.2f})")
                if results['body_score'] > 0:
                    components.append(f"body({results['body_score']:.2f})")

                print(" + ".join(components))
                print(f"Thresholds: LOW (<2.0), MEDIUM (2.0-4.9), HIGH (≥5.0)")
            """
