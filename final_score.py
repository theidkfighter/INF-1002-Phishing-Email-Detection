import re
from typing import List, Dict, Optional
from difflib import SequenceMatcher


class FinalScoreCalculator:
    """
    This class is responsible for combining multiple phishing detection signals into one overall 'risk score'
    and classifying emails into LOW, MEDIUM, or HIGH risk.
    """

    def __init__(self, domain_validator=None, threshold: float = 50.0):
        """
        Initialize the score calculator.

        Args:
            domain_validator: Instance of DomainValidator (optional).
            threshold: Score threshold above which emails are flagged.
        """
        self.domain_validator = domain_validator    # stores a domain validator instance
        self.threshold = threshold  # stores a general numeric threshold
        self.thresholds = { # define boundaries for classification
            "low": 1.0, # below 1 --> LOW risk
            "medium": 2.0   # between 1-2 --> MEDIUM; greater than 2 --> HIGH
        }

    # ------------------ Helper function: extract domain ------------------

    @staticmethod
    def _extract_domain_from_url(url: str) -> str:
        """Extract domain from a URL (simple method)."""
        if not url: # empty input returns empty string
            return ""
        s = url.strip().lower() # clean spaces, lowercase all text
        s = re.sub(r'^https?://', '', s)    # remove scheme
        s = s.split('/')[0].split(':')[0]   # remove path and port
        if s.startswith("www."):    # remove leading 'www.'
            s = s[4:]
        return s    # return the cleaned domain
    
    # ------------------ Helper function: domain similarity ------------------

    @staticmethod
    def _simple_domain_similarity(sender_domain: str, link_domains: List[str]) -> Dict:
        """
        Compare sender domain with link domains.
        Marks as suspicious if similarity ratio >= 0.8.
        Return both a numeric score and a list of details.
        """
        score = 0.0 # initialize risk score accumulator
        details = []    # store text explanations

        # guard clause: if either sender or links missing, no score
        if not sender_domain or not link_domains:
            return {"score": 0.0, "details": []}

        # loop through every link domain in the email
        for d in link_domains:
            if not d or d == sender_domain:
                continue    # skip if empty or exact match

            # compare similarity between two strings (0 = different, 1 = identical)
            ratio = SequenceMatcher(None, sender_domain, d).ratio()
            if ratio >= 0.80:   # if highly similar (e.g., wp.pl vs wp.p1)
                score += 15.0   # add 15 points for each suspicious similarity
                details.append(
                    f"Sender domain '{sender_domain}' similar to link domain '{d}' (sim={ratio:.2f})"
                )
                if score >= 45.0:  # early stop if the score already high
                    break

        # return both the score and the list of reasons        
        return {"score": score, "details": details}

    # ------------------ Main function: classify overall risk ------------------

    def classify(self, risk_index: float) -> Dict[str, str]:
        """
        Convert numeric risk_index into categorical label, LOW, MEDIUM, or HIGH.
        """
        low_t = self.thresholds["low"]  # retrive numeric boundary for 'low'
        med_t = self.thresholds["medium"]   # retrive numeric boundary for 'medium'

        # classification logic:
        if risk_index < low_t:
            risk_level = "LOW"
        elif risk_index < med_t:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"

        # return both the risk level (string) and numeric score
        return {"risk_level": risk_level, "score": risk_index}

        
        
