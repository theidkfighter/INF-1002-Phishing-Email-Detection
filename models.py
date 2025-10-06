
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List

@dataclass
class ValidationResult:

    email: str
    domain: Optional[str]
    is_trusted: bool
    message: str
    original_data: Dict[str, Any] = field(default_factory=dict)
    riskInfo: List[str] = field(default_factory=list)

@dataclass
class ValidationRequest:

    email: Optional[str] = None
    domain: Optional[str] = None
    csv_file: Optional[str] = None