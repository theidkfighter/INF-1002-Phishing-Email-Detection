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

        
        
