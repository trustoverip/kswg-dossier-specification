#!/usr/bin/env python3
# Placeholder script for sample checks
import sys
import json
import re
from pathlib import Path
import argparse

VALID_SAID_PAT = re.compile(r'^(?:[BE][A-Za-z0-9_-]{43}|0[DEFG][A-Za-z0-9_-]{86})$')

def extract_json_blocks(md_text):
    # Find all code blocks marked as json
    pattern = re.compile(r'```json\s*(.*?)```', re.DOTALL)
    return pattern.findall(md_text)

def extract_json_blocks_with_lines(md_text):
    # Returns list of (block, start_line) tuples
    blocks = []
    pattern = re.compile(r'```json\s*(.*?)```', re.DOTALL)
    for match in pattern.finditer(md_text):
        block = match.group(1)
        # Find line number
        start_pos = match.start()
        start_line = md_text[:start_pos].count('\n') + 1
        blocks.append((block, start_line))
    return blocks

def validate_json_schema_block(block, dossier_schema_id):
    try:
        import jsonschema
    except ImportError:
        print("jsonschema package not installed. Skipping schema validation.")
        return True, None, None
    try:
        obj = json.loads(block)
    except Exception:
        return False, "invalid_json", None
    if "$schema" in block:
        # Check $id field validity
        if not isinstance(obj, dict) or "$id" not in obj:
            return False, "missing_id", None
        if not VALID_SAID_PAT.match(str(obj["$id"])):
            return False, "invalid_id", obj["$id"]
        try:
            jsonschema.Draft202012Validator.check_schema(obj)
        except Exception as e:
            return False, "invalid_schema", str(e)
        # Check for allOf/$ref logic at the root level
        if "allOf" not in obj:
            return False, "missing_allOf", None
        allof = obj["allOf"]
        if not isinstance(allof, list):
            return False, "allOf_not_list", None
        found = False
        for item in allof:
            if isinstance(item, dict) and "$ref" in item:
                if item["$ref"] == dossier_schema_id:
                    found = True
        if not found:
            return False, "missing_ref", None
    return True, None, None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--md', default='spec/spec.md')
    parser.add_argument('--schema', default='spec/dossier-schema.json')
    args = parser.parse_args()

    md_path = Path(args.md)
    schema_path = Path(args.schema)
    if not md_path.exists():
        print(f"Markdown file {md_path} not found.")
        sys.exit(1)
    if not schema_path.exists():
        print(f"Schema file {schema_path} not found.")
        sys.exit(1)
    md_text = md_path.read_text()
    schema_obj = json.loads(schema_path.read_text())
    dossier_schema_id = schema_obj.get("$id")
    # Replace extract_json_blocks with extract_json_blocks_with_lines
    blocks = extract_json_blocks_with_lines(md_text)
    errors = 0
    for idx, (block, start_line) in enumerate(blocks):
        try:
            json.loads(block)
        except Exception as e:
            print(f"Block {idx+1}, beginning at line {start_line} of spec.md: Invalid JSON: {e}")
            errors += 1
            continue
        if "$schema" in block:
            valid, error_type, error_msg = validate_json_schema_block(block, dossier_schema_id)
            if not valid:
                if error_type == "missing_id":
                    print(f"Block {idx+1}, beginning at line {start_line} of spec.md: JSON Schema block missing '$id' field.")
                elif error_type == "invalid_id":
                    print(f"Block {idx+1}, beginning at line {start_line} of spec.md: JSON Schema block has invalid $id value: {error_msg}")
                elif error_type == "invalid_schema":
                    print(f"Block {idx+1}, beginning at line {start_line} of spec.md: Invalid JSON Schema. {error_msg}")
                elif error_type == "not_object":
                    print(f"Block {idx+1}, beginning at line {start_line} of spec.md: JSON Schema block is not an object.")
                elif error_type == "missing_allOf":
                    print(f"Block {idx+1}, beginning at line {start_line} of spec.md: 'allOf' key missing in schema object.")
                elif error_type == "allOf_not_list":
                    print(f"Block {idx+1}, beginning at line {start_line} of spec.md: 'allOf' is not a list.")
                elif error_type == "missing_ref":
                    print(f"Block {idx+1}, beginning at line {start_line} of spec.md: Missing $ref to dossier schema.")
                else:
                    print(f"Block {idx+1}, beginning at line {start_line} of spec.md: Unknown error in JSON Schema block.")
                errors += 1
    if errors:
        print(f"Found {errors} error(s) in JSON code blocks.")
        sys.exit(1)
    print("All JSON code blocks passed checks.")
    sys.exit(0)

if __name__ == "__main__":
    main()
