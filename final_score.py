import re
from typing import List, Dict, Optional
from difflib import SequenceMatcher

#😥😥😥🙃🙃🙃Not working....

class FinalScoreCalculator:
    """
    Class to combine multiple phishing detection signals into a final risk score.
    """

    def __init__(self, domain_validator=None, threshold: float = 50.0):
        
        """
        Initialize the scorer.

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
        self,
        sender_email: str,
        subject: str,
        body: str,
        links: Optional[List[str]] = None,
        keyword_result: Optional[Dict] = None,
        edit_distance_result: Optional[int] = None,
        vector_domain_result: Optional[Dict] = None,
        phrase_result: Optional[Dict] = None,
    ) -> Dict:
        """
        Compute final phishing risk score.

        Args:
            sender_email: Sender email address.
            subject: Email subject text.
            body: Email body text.
            links: List of URLs found in the email.
            keyword_result: Precomputed keyword module result (optional).
            edit_distance_result: Precomputed edit-distance result (optional).
            vector_domain_result: Precomputed domain similarity result (optional).
            phrase_result: Precomputed suspicious phrase result (optional).

        Returns:
            dict {
                "score": float,
                "label": "Phishing"/"Safe",
                "risk_level": "HIGH"/"MEDIUM"/"LOW",
                "details": [list of reasons]
            }
        """
        if links is None:
            links = []

        total_points = 0.0
        details: List[str] = []

        # ------------------ 1. Keyword analysis ------------------
        kw_raw = float(keyword_result.get("total_score", 0.0)) if keyword_result else 0.0
        kw_points = (min(max(kw_raw, 0.0), 10.0) / 10.0) * 30.0
        total_points += kw_points
        if kw_raw > 0:
            details.append(f"Keywords: raw={kw_raw:.2f} -> +{kw_points:.1f} pts")

        # ------------------ 2. Domain validation ------------------
        dv_result = None
        if self.domain_validator is not None:
            try:
                dv_result = self.domain_validator.validate_email(sender_email)
                if getattr(dv_result, "is_trusted", False):
                    details.append(f"Sender domain '{dv_result.domain}' is trusted -> +0 pts")
                else:
                    total_points += 20.0
                    details.append(f"Sender domain '{dv_result.domain}' not trusted -> +20.0 pts")
            except Exception:
                dv_result = None

        if dv_result is None:
            sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
            if not re.match(r'^[a-z0-9\.\-]+$', sender_domain):
                total_points += 25.0
                details.append(f"Invalid sender email/domain format -> +25.0 pts")

        # ------------------ 3. Edit distance ------------------
        ed_raw = int(edit_distance_result or 0)
        ed_points = (min(max(ed_raw, 0), 2) / 2.0) * 20.0
        total_points += ed_points
        if ed_raw > 0:
            details.append(f"Edit-distance: raw={ed_raw} -> +{ed_points:.1f} pts")

        # ------------------ 4. Domain similarity ------------------
        link_domains = [self._extract_domain_from_url(u) for u in links if u]
        if vector_domain_result:
            vd_raw = float(vector_domain_result.get("score", 0.0))
            vd_points = (min(max(vd_raw, 0.0), 45.0) / 45.0) * 25.0
            total_points += vd_points
            details.extend(vector_domain_result.get("details", []))
        else:
            sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
            sim_res = self._simple_domain_similarity(sender_domain, link_domains)
            vd_raw = float(sim_res.get("score", 0.0))
            vd_points = (min(vd_raw, 45.0) / 45.0) * 25.0
            total_points += vd_points
            details.extend(sim_res.get("details", []))

        # ------------------ 5. Suspicious phrases ------------------
        if phrase_result:
            ph_raw = float(phrase_result.get("score", 0.0))
            ph_points = (min(max(ph_raw, 0.0), 10.0) / 10.0) * 20.0
            total_points += ph_points
            details.append(f"Phrase scoring: raw={ph_raw:.2f} -> +{ph_points:.1f} pts")

        # ------------------ 6. IP in links ------------------
        for u in links:
            if re.search(r'http[s]?://\d{1,3}(\.\d{1,3}){3}', u):
                total_points += 15.0
                details.append(f"Link contains IP address '{u}' -> +15.0 pts")
                break

        # ------------------ Final aggregation ------------------
        final_score = max(0.0, min(total_points, 100.0))
        label = "Phishing" if final_score >= self.threshold else "Safe"

        if final_score >= 70:
            risk_level = "HIGH"
        elif final_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        if not details:
            details = ["No suspicious signs detected."]

        return {
            "score": round(final_score, 2),
            "label": label,
            "risk_level": risk_level,
            "details": details,
        }
