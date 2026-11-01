"""
Strict JSON Schema and argument validation engine.
Prevents parameter pollution, unexpected properties, and type coercion exploits.
"""

import re
from typing import Any


class SchemaValidationError(Exception):
    def __init__(self, message: str, violations: list[str]) -> None:
        super().__init__(message)
        self.violations = violations


class StrictSchemaValidator:
    """Validates tool arguments against strict schema rules with zero type coercion."""

    @staticmethod
    def validate(schema: dict[str, Any], arguments: dict[str, Any]) -> tuple[bool, list[str]]:
        violations: list[str] = []

        if not isinstance(arguments, dict):
            return False, ["Tool arguments must be a JSON object (dictionary)."]

        properties: dict[str, Any] = schema.get("properties", {})
        required_fields: list[str] = schema.get("required", [])
        allow_additional: bool = schema.get("additionalProperties", False)

        # 1. Required field checks
        for req in required_fields:
            if req not in arguments:
                violations.append(f"Missing required argument: '{req}'")

        # 2. Strict rejection of unexpected properties (parameter pollution defense)
        if not allow_additional:
            for key in arguments.keys():
                if key not in properties:
                    violations.append(f"Disallowed additional argument: '{key}' (additionalProperties=false)")

        # 3. Type checking & constraint bounds
        for key, val in arguments.items():
            if key not in properties:
                continue

            prop_def = properties[key]
            expected_type = prop_def.get("type")

            # Check nullability
            if val is None:
                if prop_def.get("nullable", False):
                    continue
                violations.append(f"Field '{key}' cannot be null.")
                continue

            if expected_type == "string":
                if not isinstance(val, str):
                    violations.append(f"Field '{key}' must be of type string, got {type(val).__name__}")
                    continue
                min_len = prop_def.get("minLength")
                if min_len is not None and len(val) < min_len:
                    violations.append(f"Field '{key}' length {len(val)} is less than minLength {min_len}")
                max_len = prop_def.get("maxLength")
                if max_len is not None and len(val) > max_len:
                    violations.append(f"Field '{key}' length {len(val)} exceeds maxLength {max_len}")
                pattern = prop_def.get("pattern")
                if pattern is not None:
                    if not re.search(pattern, val):
                        violations.append(f"Field '{key}' does not match required regex pattern: {pattern}")
                enum_vals = prop_def.get("enum")
                if enum_vals is not None and val not in enum_vals:
                    violations.append(f"Field '{key}' value '{val}' not in allowed enum: {enum_vals}")

            elif expected_type == "integer":
                # In Python bool is a subclass of int, so explicitly reject bool
                if isinstance(val, bool) or not isinstance(val, int):
                    violations.append(f"Field '{key}' must be an integer, got {type(val).__name__}")
                    continue
                minimum = prop_def.get("minimum")
                if minimum is not None and val < minimum:
                    violations.append(f"Field '{key}' value {val} is below minimum {minimum}")
                maximum = prop_def.get("maximum")
                if maximum is not None and val > maximum:
                    violations.append(f"Field '{key}' value {val} exceeds maximum {maximum}")

            elif expected_type == "number":
                if isinstance(val, bool) or not isinstance(val, (int, float)):
                    violations.append(f"Field '{key}' must be a number, got {type(val).__name__}")
                    continue
                minimum = prop_def.get("minimum")
                if minimum is not None and val < minimum:
                    violations.append(f"Field '{key}' value {val} is below minimum {minimum}")
                maximum = prop_def.get("maximum")
                if maximum is not None and val > maximum:
                    violations.append(f"Field '{key}' value {val} exceeds maximum {maximum}")

            elif expected_type == "boolean":
                if not isinstance(val, bool):
                    violations.append(f"Field '{key}' must be a boolean, got {type(val).__name__}")

            elif expected_type == "array":
                if not isinstance(val, list):
                    violations.append(f"Field '{key}' must be an array, got {type(val).__name__}")
                    continue
                min_items = prop_def.get("minItems")
                if min_items is not None and len(val) < min_items:
                    violations.append(f"Field '{key}' items count {len(val)} is below minItems {min_items}")
                max_items = prop_def.get("maxItems")
                if max_items is not None and len(val) > max_items:
                    violations.append(f"Field '{key}' items count {len(val)} exceeds maxItems {max_items}")
                item_def = prop_def.get("items")
                if item_def and isinstance(item_def, dict):
                    item_type = item_def.get("type")
                    if item_type == "string":
                        for idx, item in enumerate(val):
                            if not isinstance(item, str):
                                violations.append(f"Field '{key}[{idx}]' must be a string, got {type(item).__name__}")

            elif expected_type == "object":
                if not isinstance(val, dict):
                    violations.append(f"Field '{key}' must be an object, got {type(val).__name__}")

        return len(violations) == 0, violations

