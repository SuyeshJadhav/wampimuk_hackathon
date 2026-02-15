"""
High-Performance DLP Scanner

Scans request body for sensitive data
Returns score and findings

Optimized for speed:
- Precompiled regex
- Single pass scan
- Minimal allocations
"""

from typing import Dict, List

from .dlp_rules import DLP_PATTERNS
from .dlp_config import SENSITIVITY_SCORES


class DLPScanner:


    def __init__(self):

        # Local reference = faster lookup
        self.patterns = DLP_PATTERNS
        self.scores = SENSITIVITY_SCORES


    def scan(self, body: str) -> Dict:
        """
        Scan text for sensitive data

        Returns:
        {
            total_score: int,
            findings: list
        }
        """

        if not body:
            return {
                "total_score": 0,
                "findings": []
            }


        findings: List[Dict] = []
        total_score = 0


        # Scan using precompiled regex
        for data_type, pattern in self.patterns.items():

            matches = pattern.findall(body)

            if matches:

                score = self.scores.get(data_type, 0)

                total_score += score * len(matches)


                findings.append({

                    "type": data_type,
                    "matches": len(matches),
                    "score": score,

                })


        return {

            "total_score": total_score,
            "findings": findings

        }