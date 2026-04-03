import json
from pathlib import Path
from enum import Enum

_constants_path = Path(__file__).resolve().parent.parent.parent / "src" / "Shared" / "constants.json"
_config = json.loads(_constants_path.read_text())

MAX_TOKENS_PER_RULE: int = _config["MAX_TOKENS_PER_RULE"]
MAX_NEEDLE_LENGTH: int = _config["MAX_NEEDLE_LENGTH"]
MAX_TOTAL_PREDS: int = _config["MAX_TOTAL_PREDS"]
MAX_RULES_PER_MAP: int = _config["MAX_RULES_PER_MAP"]
MAX_REGEX_DFA_STATES: int = _config["MAX_REGEX_DFA_STATES"]

ALLOWED_ACTIONS: set = set(_config["actions"])

# Valid event types for sigma rules (FORK and EXIT are not supported)
VALID_EVENT_TYPES: set = {
    "CHMOD",
    "CHOWN", 
    "READ",
    "WRITE",
    "UNLINK",
    "FILE_CREATE",
    "EXEC",
    "RENAME",
    "NETWORK",
    "MKDIR",
    "RMDIR",
}

FILE_TYPE_ENUM: dict = _config["file_types"]
CONNECTION_DIRECTION_ENUM: dict = _config["connection_direction"]
RULE_FIELD_TYPES: dict = _config["rule_field_types"]

AF_INET: int = _config["AF_INET"]
AF_INET6: int = _config["AF_INET6"]

class OperatorType(Enum):
    """Operator types for postfix tokens."""
    OPERATOR_PREDICATE = _config["operator_types"]["OPERATOR_PREDICATE"]
    OPERATOR_AND = _config["operator_types"]["OPERATOR_AND"]
    OPERATOR_OR = _config["operator_types"]["OPERATOR_OR"]
    OPERATOR_NOT = _config["operator_types"]["OPERATOR_NOT"]

class StringType(Enum):
    """String types for rule strings."""
    DEFAULT = _config["string_type"]["STRING_TYPE_DEFAULT"]
    CONTAINS = _config["string_type"]["STRING_TYPE_CONTAINS"]
    REGEX = _config["string_type"]["STRING_TYPE_REGEX"]

COMPARISON_TYPE_EXACT_MATCH: str = _config["comparison_types"]["COMPARISON_TYPE_EXACT_MATCH"]
COMPARISON_TYPE_CONTAINS: str = _config["comparison_types"]["COMPARISON_TYPE_CONTAINS"]
COMPARISON_TYPE_STARTS_WITH: str = _config["comparison_types"]["COMPARISON_TYPE_STARTS_WITH"]
COMPARISON_TYPE_ENDS_WITH: str = _config["comparison_types"]["COMPARISON_TYPE_ENDS_WITH"]
COMPARISON_TYPE_EQUAL: str = _config["comparison_types"]["COMPARISON_TYPE_EQUAL"]
COMPARISON_TYPE_ABOVE: str = _config["comparison_types"]["COMPARISON_TYPE_ABOVE"]
COMPARISON_TYPE_BELOW: str = _config["comparison_types"]["COMPARISON_TYPE_BELOW"]
COMPARISON_TYPE_EQUAL_ABOVE: str = _config["comparison_types"]["COMPARISON_TYPE_EQUAL_ABOVE"]
COMPARISON_TYPE_EQUAL_BELOW: str = _config["comparison_types"]["COMPARISON_TYPE_EQUAL_BELOW"]
COMPARISON_TYPE_REGEX: str = _config["comparison_types"]["COMPARISON_TYPE_REGEX"]

