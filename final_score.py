import re
from typing import List, Dict, Optional
from difflib import SequenceMatcher


class FinalScoreCalculator:
    """
    Class to combine multiple phishing detection signals into a final risk score.
    """

    def __init__(self, domain_validator=None, threshold: float = 50.0):
        """
        Initialize the scorer.

        Args:
            domain_validator: Instance of DomainValidator (optional).
            threshold: Score threshold above which emails are flagged.
        """
        self.domain_validator = domain_validator
        self.threshold = threshold

    # ------------------------------
    # Helpers
    # ------------------------------
    @staticmethod
    def _extract_domain_from_url(url: str) -> str:
        """Extract domain from a URL (simple method)."""
        if not url:
            return ""
        s = url.strip().lower()
        s = re.sub(r'^https?://', '', s)  # remove scheme
        s = s.split('/')[0].split(':')[0]  # remove path and port
        if s.startswith("www."):
            s = s[4:]
        return s

    @staticmethod
    def _simple_domain_similarity(sender_domain: str, link_domains: List[str]) -> Dict:
        """
        Compare sender domain with link domains.
        Marks as suspicious if similarity ratio >= 0.8.
        """
        score = 0.0
        details = []
        if not sender_domain or not link_domains:
            return {"score": 0.0, "details": []}

        for d in link_domains:
            if not d or d == sender_domain:
                continue
            ratio = SequenceMatcher(None, sender_domain, d).ratio()
            if ratio >= 0.80:
                score += 15.0
                details.append(
                    f"Sender domain '{sender_domain}' similar to link domain '{d}' (sim={ratio:.2f})"
                )
                if score >= 45.0:  # early stop
                    break
        return {"score": score, "details": details}

    # ------------------------------
    # Main Scoring
    # ------------------------------
    def score(
        self, riskIndex
    ) -> Dict:

        totalriskIndex = riskIndex

       

        if totalriskIndex == 0:
            risk_level = "SAFE"
        else:
            risk_level="PHISHING"



        return {
            "risk_level": risk_level,
        }
