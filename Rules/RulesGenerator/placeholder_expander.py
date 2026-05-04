"""Placeholder expansion for Sigma rules.

Handles the |expand modifier by replacing %placeholder_name% patterns
with actual values from a placeholder definitions file.

Uses pySigma's SigmaString.insert_placeholders() internally
to parse the %name% pattern consistently with the Sigma specification.
"""
import yaml
from typing import Dict, List, Any, Optional
from sigma.types import SigmaString, Placeholder


def load_placeholders(file_path: str) -> Dict[str, List]:
    """Load placeholder definitions from a YAML file.

    Expected format:
        shell_names:
          - bash
          - zsh
          - fish
        suspicious_paths:
          - /tmp/
          - /var/tmp/
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise Exception(f"Failed to parse placeholder file '{file_path}': {e}")
    except IOError as e:
        raise Exception(f"Failed to read placeholder file '{file_path}': {e}")

    if data is None:
        raise Exception(f"Placeholder file '{file_path}' is empty")
    if not isinstance(data, dict):
        raise Exception(
            f"Placeholder file '{file_path}' must contain a YAML mapping, "
            f"got {type(data).__name__}")

    for name, values in data.items():
        if not isinstance(name, str):
            raise Exception(
                f"Placeholder name must be a string, got {type(name).__name__}")
        if not isinstance(values, list):
            raise Exception(
                f"Placeholder '{name}' must map to a list, got {type(values).__name__}")
        if len(values) == 0:
            raise Exception(
                f"Placeholder '{name}' must have at least one value (empty lists not allowed)")
        for i, v in enumerate(values):
            if not isinstance(v, (str, int, float)):
                raise Exception(
                    f"Placeholder '{name}' item {i}: values must be strings or numbers, "
                    f"got {type(v).__name__}")

    return data


def _parse_placeholder_name(value: str) -> Optional[str]:
    """Extract placeholder name from a value using pySigma's parsing.

    Returns the placeholder name if the entire value is a single %name% pattern,
    None otherwise.
    """
    if not isinstance(value, str):
        return None

    sigma_str = SigmaString(value)
    sigma_str = sigma_str.insert_placeholders()

    if len(sigma_str.s) == 1 and isinstance(sigma_str.s[0], Placeholder):
        return sigma_str.s[0].name

    return None


def _has_expand_modifier(field_key: str) -> bool:
    parts = field_key.split("|")
    return any(p.strip().lower() == "expand" for p in parts[1:])


def _remove_expand_modifier(field_key: str) -> str:
    parts = field_key.split("|")
    filtered = [parts[0]] + [p for p in parts[1:] if p.strip().lower() != "expand"]
    return "|".join(filtered)


def _expand_field_value(value, placeholders: Dict[str, List],
                        field_key: str, sel_name: str, rule_file: str):
    """Expand a field value that may contain %placeholder% patterns.

    Supports:
      - Single string: "%name%" -> [val1, val2, ...]
      - List of strings: ["%a%", "literal", "%b%"] -> expanded + literal values
    """
    if isinstance(value, str):
        name = _parse_placeholder_name(value)
        if name is not None:
            if name not in placeholders:
                raise Exception(
                    f"Unknown placeholder '%{name}%' in field '{field_key}', "
                    f"selection '{sel_name}' in '{rule_file}'. "
                    f"Available placeholders: {sorted(placeholders.keys())}")
            return list(placeholders[name])
        return value

    if isinstance(value, list):
        expanded = []
        for v in value:
            if isinstance(v, str):
                name = _parse_placeholder_name(v)
                if name is not None:
                    if name not in placeholders:
                        raise Exception(
                            f"Unknown placeholder '%{name}%' in field '{field_key}', "
                            f"selection '{sel_name}' in '{rule_file}'. "
                            f"Available placeholders: {sorted(placeholders.keys())}")
                    expanded.extend(placeholders[name])
                else:
                    expanded.append(v)
            else:
                expanded.append(v)
        return expanded

    return value


def _expand_selection_dict(sel_dict: Dict[str, Any], placeholders: Optional[Dict[str, List]],
                           sel_name: str, rule_file: str) -> Dict[str, Any]:
    new_dict = {}

    for field_key, values in sel_dict.items():
        if not _has_expand_modifier(field_key):
            new_dict[field_key] = values
            continue

        if not placeholders:
            raise Exception(
                f"Field '{field_key}' in selection '{sel_name}' in '{rule_file}' uses the "
                f"'|expand' modifier but no placeholder file was provided. "
                f"Use -p/--placeholders to specify a placeholder values file.")

        new_key = _remove_expand_modifier(field_key)
        expanded = _expand_field_value(values, placeholders, field_key, sel_name, rule_file)
        new_dict[new_key] = expanded

    return new_dict


def expand_detection_placeholders(detection: Dict[str, Any],
                                  placeholders: Optional[Dict[str, List]],
                                  rule_file: str) -> Dict[str, Any]:
    """Expand all |expand modifier fields in a detection dict.

    For each field with |expand:
      1. Parses %name% values using pySigma's placeholder syntax
      2. Replaces them with the actual values from the placeholders dict
      3. Removes the |expand modifier from the field key
    """
    new_detection = {}

    for sel_name, sel_value in detection.items():
        if sel_name == "condition":
            new_detection[sel_name] = sel_value
            continue

        if isinstance(sel_value, dict):
            new_detection[sel_name] = _expand_selection_dict(
                sel_value, placeholders, sel_name, rule_file)
        elif isinstance(sel_value, list):
            if sel_value and isinstance(sel_value[0], dict):
                new_detection[sel_name] = [
                    _expand_selection_dict(item, placeholders, sel_name, rule_file)
                    for item in sel_value
                ]
            else:
                new_detection[sel_name] = sel_value
        else:
            new_detection[sel_name] = sel_value

    return new_detection
