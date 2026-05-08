from pydantic import BaseModel
from typing import List, Dict

class Violation(BaseModel):
    policy: str
    severity: str
    description: str
    remediation: str

class AuditReport(BaseModel):
    secure: bool
    scanned_resources: int
    violations: List[Violation]

class ReportGenerator:
    @staticmethod
    def generate(violations: List[Dict], scanned_resources: int) -> AuditReport:
        """
        Formats the output of the validation into a standardized JSON response.
        """
        return AuditReport(
            secure=len(violations) == 0,
            scanned_resources=scanned_resources,
            violations=[Violation(**v) for v in violations]
        )