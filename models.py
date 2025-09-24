
from dataclasses import dataclass, field
from typing import Dict, Any, Optional

@dataclass
class ValidationResult:

    email: str
    domain: Optional[str]
    is_trusted: bool
    message: str
    original_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ValidationRequest:

    email: Optional[str] = None
    domain: Optional[str] = None
    csv_file: Optional[str] = None