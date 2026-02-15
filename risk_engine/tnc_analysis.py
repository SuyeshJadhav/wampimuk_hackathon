import re

class TnCAnalyzer:
    def __init__(self):
        # Define "Red Flags" and their risk weight (1-10)
        # These can be expanded or moved to a config file later [cite: 4]
        self.risk_patterns = {
            "data_selling": (r"sell|share|transfer.*third parties|affiliates", 8),
            "arbitration": (r"binding arbitration|waive.*class action", 7),
            "tracking": (r"track.*behavior|cross-site tracking|cookies.*third-party", 5),
            "retention": (r"retain.*indefinitely|keep.*data.*forever", 6),
            "no_liability": (r"not liable|as is|no warranty|at your own risk", 4)
        }

    def analyze_text(self, text: str):
        """
        Analyzes the provided text for risky clauses and returns a summary. [cite: 5, 12]
        """
        findings = []
        total_score = 0
        
        # Clean the text slightly for better matching
        clean_text = text.lower().strip()

        for category, (pattern, weight) in self.risk_patterns.items():
            matches = re.findall(pattern, clean_text)
            if matches:
                # Add the weighted score for each unique category found
                total_score += weight
                findings.append({
                    "category": category,
                    "risk_level": weight,
                    "count": len(matches),
                    "snippet": f"Found references to: {category.replace('_', ' ')}"
                })

        # Normalize score to a 0-100 scale [cite: 12]
        normalized_score = min(total_score * 5, 100)
        
        return {
            "tnc_score": normalized_score,
            "findings": findings,
            "status": "DANGER" if normalized_score > 70 else "WARNING" if normalized_score > 30 else "SAFE"
        }

# Example usage for testing
if __name__ == "__main__":
    sample_text = "We may sell your data to third parties and use tracking cookies for behavioral ads."
    analyzer = TnCAnalyzer()
    print(analyzer.analyze_text(sample_text))