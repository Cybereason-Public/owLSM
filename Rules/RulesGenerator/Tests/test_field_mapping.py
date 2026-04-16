"""Tests for field_mapping (external field names -> owLSM)."""

import pytest

from field_mapping import apply_field_mapping_to_detection, load_field_mapping_file
from sigma_rule_loader import load_sigma_rules


class TestLoadFieldMappingFile:
    def test_rejects_invalid_destination(self, tmp_path):
        p = tmp_path / "map.yml"
        p.write_text("CustomX: not_a_real_owlsm_field\n")
        with pytest.raises(Exception, match="not a valid owLSM rule field"):
            load_field_mapping_file(str(p))

    def test_accepts_valid_destination(self, tmp_path):
        p = tmp_path / "map.yml"
        p.write_text("VendorImage: process.file.filename\n")
        m = load_field_mapping_file(str(p))
        assert m == {"VendorImage": "process.file.filename"}

    def test_empty_file_returns_empty_mapping(self, tmp_path):
        p = tmp_path / "empty.yml"
        p.write_text("# only comment\n")
        assert load_field_mapping_file(str(p)) == {}

    def test_explicit_null_returns_empty_mapping(self, tmp_path):
        p = tmp_path / "null.yml"
        p.write_text("~\n")
        assert load_field_mapping_file(str(p)) == {}

    def test_rejects_non_dict_root(self, tmp_path):
        p = tmp_path / "bad.yml"
        p.write_text("- a\n- b\n")
        with pytest.raises(Exception, match="expected a YAML mapping"):
            load_field_mapping_file(str(p))

    def test_rejects_non_string_key(self, tmp_path):
        p = tmp_path / "bad.yml"
        p.write_text("1: process.pid\n")
        with pytest.raises(Exception, match="mapping keys and values must be strings"):
            load_field_mapping_file(str(p))

    def test_rejects_non_string_value(self, tmp_path):
        p = tmp_path / "bad.yml"
        p.write_text("VendorX: 99\n")
        with pytest.raises(Exception, match="must be strings"):
            load_field_mapping_file(str(p))


class TestApplyFieldMapping:
    """Structured rewrites only (keys + fieldref scalars); literals never substring-matched."""

    def test_empty_mapping_is_noop(self):
        detection = {"sel": {"VendorImage": "x"}, "condition": "sel"}
        original = {"sel": {"VendorImage": "x"}, "condition": "sel"}
        apply_field_mapping_to_detection(detection, {})
        assert detection == original

    def test_remaps_key_with_single_modifier(self):
        detection = {"sel": {"VendorImage|contains": "evil"}, "condition": "sel"}
        apply_field_mapping_to_detection(detection, {"VendorImage": "process.file.filename"})
        assert detection["sel"] == {"process.file.filename|contains": "evil"}

    def test_long_source_alias_name(self):
        long_name = "v_" + ("segment." * 40) + "tail"
        assert len(long_name) > 120
        detection = {"sel": {f"{long_name}|endswith": ".dll"}, "condition": "sel"}
        apply_field_mapping_to_detection(detection, {long_name: "process.file.filename"})
        assert detection["sel"] == {"process.file.filename|endswith": ".dll"}

    def test_short_single_character_source_alias(self):
        detection = {"sel": {"z": 1}, "condition": "sel"}
        apply_field_mapping_to_detection(detection, {"z": "process.pid"})
        assert detection["sel"] == {"process.pid": 1}

    def test_dotted_path_style_vendor_key(self):
        detection = {
            "sel": {"vendor.event.target.path|startswith": "/tmp"},
            "condition": "sel",
        }
        apply_field_mapping_to_detection(
            detection, {"vendor.event.target.path": "target.file.path"}
        )
        assert detection["sel"] == {"target.file.path|startswith": "/tmp"}

    def test_modifier_chain_contains_all_order_preserved(self):
        detection = {"sel": {"ExtCmd|contains|all": ["a", "b"]}, "condition": "sel"}
        apply_field_mapping_to_detection(detection, {"ExtCmd": "process.cmd"})
        assert detection["sel"] == {"process.cmd|contains|all": ["a", "b"]}

    def test_string_literal_equals_alias_not_remapped_without_fieldref(self):
        detection = {"sel": {"process.cmd": "VendorImage"}, "condition": "sel"}
        apply_field_mapping_to_detection(
            detection, {"VendorImage": "process.file.filename"}
        )
        assert detection["sel"]["process.cmd"] == "VendorImage"

    def test_string_literal_contains_alias_as_substring(self):
        detection = {
            "sel": {"process.cmd": "prefix/VendorImageToken/suffix"},
            "condition": "sel",
        }
        apply_field_mapping_to_detection(
            detection, {"VendorImageToken": "process.file.filename"}
        )
        assert detection["sel"]["process.cmd"] == "prefix/VendorImageToken/suffix"

    def test_regex_pattern_substring_and_anchors_unchanged(self):
        detection = {
            "sel": {
                "process.cmd|re": r".*VendorTok.*",
                "process.file.filename|re": r"^VendorTok$",
            },
            "condition": "sel",
        }
        apply_field_mapping_to_detection(
            detection, {"VendorTok": "process.pid", "unused": "parent_process.pid"}
        )
        assert detection["sel"]["process.cmd|re"] == r".*VendorTok.*"
        assert detection["sel"]["process.file.filename|re"] == r"^VendorTok$"

    def test_fieldref_target_remapped_exact_match_only(self):
        detection = {
            "sel": {"process.file.filename|fieldref": "VendorParentName"},
            "condition": "sel",
        }
        apply_field_mapping_to_detection(
            detection, {"VendorParentName": "parent_process.file.filename"}
        )
        assert detection["sel"]["process.file.filename|fieldref"] == (
            "parent_process.file.filename"
        )

    def test_fieldref_target_not_in_mapping_unchanged(self):
        detection = {
            "sel": {"process.pid|fieldref": "parent_process.pid"},
            "condition": "sel",
        }
        apply_field_mapping_to_detection(detection, {"Other": "process.cmd"})
        assert detection["sel"] == {"process.pid|fieldref": "parent_process.pid"}

    def test_fieldref_with_string_modifier_remaps_key_and_value(self):
        detection = {
            "sel": {
                "ExtLeft|fieldref|startswith": "ExtRight",
            },
            "condition": "sel",
        }
        apply_field_mapping_to_detection(
            detection,
            {
                "ExtLeft": "process.file.path",
                "ExtRight": "parent_process.file.path",
            },
        )
        assert detection["sel"] == {
            "process.file.path|fieldref|startswith": "parent_process.file.path"
        }

    def test_fieldref_neq_reversed_modifier_order(self):
        detection = {
            "sel": {"process.pid|neq|fieldref": "ExtParentPid"},
            "condition": "sel",
        }
        apply_field_mapping_to_detection(
            detection, {"ExtParentPid": "parent_process.pid"}
        )
        assert detection["sel"] == {"process.pid|neq|fieldref": "parent_process.pid"}

    def test_list_or_branch_dicts_both_remapped(self):
        detection = {
            "sel": [
                {"ExtA": "1"},
                {"ExtB|gt": 2},
            ],
            "condition": "sel",
        }
        apply_field_mapping_to_detection(
            detection, {"ExtA": "process.pid", "ExtB": "process.ppid"}
        )
        assert detection["sel"] == [{"process.pid": "1"}, {"process.ppid|gt": 2}]

    def test_multiple_selections(self):
        detection = {
            "a": {"X": "v"},
            "b": {"Y|contains": "w"},
            "condition": "a and b",
        }
        apply_field_mapping_to_detection(detection, {"X": "process.pid", "Y": "process.cmd"})
        assert detection["a"] == {"process.pid": "v"}
        assert detection["b"] == {"process.cmd|contains": "w"}
        assert detection["condition"] == "a and b"

    def test_case_sensitive_source_keys(self):
        detection = {"sel": {"Ab": "1", "ab": "2"}, "condition": "sel"}
        apply_field_mapping_to_detection(detection, {"ab": "process.pid"})
        assert detection["sel"] == {"Ab": "1", "process.pid": "2"}

    def test_keyword_list_selection_not_traversed(self):
        detection = {
            "keywords": ["VendorImage", "malware"],
            "condition": "keywords",
        }
        apply_field_mapping_to_detection(
            detection, {"VendorImage": "process.file.filename", "malware": "process.cmd"}
        )
        assert detection["keywords"] == ["VendorImage", "malware"]

    def test_keyword_all_form_not_traversed(self):
        detection = {
            "keywords": {"|all": ["VendorImage", "other"]},
            "condition": "keywords",
        }
        apply_field_mapping_to_detection(
            detection, {"VendorImage": "process.file.filename"}
        )
        assert detection["keywords"] == {"|all": ["VendorImage", "other"]}


class TestLoadSigmaRulesWithMapping:
    def test_external_fields_load_after_mapping(self, tmp_path):
        rules_dir = tmp_path / "rules_only"
        rules_dir.mkdir()
        map_path = tmp_path / "fields.yml"
        map_path.write_text(
            "VendorImage: process.file.filename\n"
            "VendorParentImage: parent_process.file.filename\n"
        )
        (rules_dir / "rule.yml").write_text(
            """
id: 92001
description: "mapping e2e"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        VendorImage|contains: malware
        process.file.filename|fieldref: VendorParentImage
    condition: sel
"""
        )
        rules = load_sigma_rules(
            str(rules_dir), field_mapping=load_field_mapping_file(str(map_path))
        )
        assert len(rules) == 1
        sel = rules[0].detection["sel"]
        assert sel == {
            "process.file.filename|contains": "malware",
            "process.file.filename|fieldref": "parent_process.file.filename",
        }

    def test_keyword_rule_with_mapping_collision_strings_unchanged(self, tmp_path):
        """Mapping keys that equal keyword tokens must not rewrite keyword selections."""
        rules_dir = tmp_path / "rules_only"
        rules_dir.mkdir()
        map_path = tmp_path / "map.yml"
        map_path.write_text(
            "malware: process.cmd\n"
            "VendorImage: process.file.filename\n"
        )
        (rules_dir / "rule.yml").write_text(
            '''
id: 92100
description: "keywords plus mapping"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    keywords:
        - "malware"
        - "VendorImage"
    condition: keywords
'''
        )
        rules = load_sigma_rules(
            str(rules_dir), field_mapping=load_field_mapping_file(str(map_path))
        )
        assert rules[0].detection["keywords"] == ["malware", "VendorImage"]

    def test_fieldref_with_modifier_loads_with_mapping(self, tmp_path):
        rules_dir = tmp_path / "rules_only"
        rules_dir.mkdir()
        map_path = tmp_path / "map.yml"
        map_path.write_text(
            "ExtLeft: process.file.path\n"
            "ExtRight: parent_process.file.path\n"
        )
        (rules_dir / "rule.yml").write_text(
            """
id: 92101
description: "fieldref startswith with mapping"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        ExtLeft|fieldref|startswith: ExtRight
    condition: sel
"""
        )
        rules = load_sigma_rules(
            str(rules_dir), field_mapping=load_field_mapping_file(str(map_path))
        )
        assert rules[0].detection["sel"] == {
            "process.file.path|fieldref|startswith": "parent_process.file.path"
        }

    def test_regex_with_vendor_token_in_pattern_loads(self, tmp_path):
        rules_dir = tmp_path / "rules_only"
        rules_dir.mkdir()
        map_path = tmp_path / "map.yml"
        map_path.write_text("ExtCmd: process.cmd\n")
        (rules_dir / "rule.yml").write_text(
            r"""
id: 92102
description: "regex contains vendor token as text only"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        ExtCmd|re: '.*VendorTok.*'
    condition: sel
"""
        )
        rules = load_sigma_rules(
            str(rules_dir), field_mapping=load_field_mapping_file(str(map_path))
        )
        assert rules[0].detection["sel"] == {"process.cmd|re": r".*VendorTok.*"}

    def test_regex_value_equal_mapping_key_not_replaced(self, tmp_path):
        """Full pipeline: |re pattern that exactly equals another mapping key is still a literal pattern."""
        rules_dir = tmp_path / "rules_only"
        rules_dir.mkdir()
        map_path = tmp_path / "map.yml"
        map_path.write_text(
            "ExtCmd: process.cmd\n"
            "MapRegexKey: process.file.filename\n"
        )
        (rules_dir / "rule.yml").write_text(
            """
id: 92103
description: "regex body equals mapping key name"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        ExtCmd|re: MapRegexKey
    condition: sel
"""
        )
        rules = load_sigma_rules(
            str(rules_dir), field_mapping=load_field_mapping_file(str(map_path))
        )
        assert rules[0].detection["sel"] == {"process.cmd|re": "MapRegexKey"}

    def test_string_value_equal_mapping_key_not_replaced(self, tmp_path):
        """Full pipeline: scalar string value that equals a mapping key is not rewritten."""
        rules_dir = tmp_path / "rules_only"
        rules_dir.mkdir()
        map_path = tmp_path / "map.yml"
        map_path.write_text(
            "ExtCmd: process.cmd\n"
            "MapStrKey: process.file.filename\n"
        )
        (rules_dir / "rule.yml").write_text(
            """
id: 92104
description: "string value equals mapping key"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        ExtCmd: MapStrKey
    condition: sel
"""
        )
        rules = load_sigma_rules(
            str(rules_dir), field_mapping=load_field_mapping_file(str(map_path))
        )
        assert rules[0].detection["sel"] == {"process.cmd": "MapStrKey"}

    def test_nested_vendor_names_filePath_and_ProcessfilePath(self, tmp_path):
        """Vendor token ``ProcessfilePath`` embeds ``filePath``; only exact keys remap; literals unchanged.

        ``ProcessfilePath`` must appear in the mapping so the rule validates after load; the interesting
        case is ``process.cmd`` containing ``ProcessfilePath`` while ``filePath`` is also a map key.
        """
        rules_dir = tmp_path / "rules_only"
        rules_dir.mkdir()
        map_path = tmp_path / "map.yml"
        map_path.write_text(
            "filePath: process.file.path\n"
            "ProcessfilePath: parent_process.file.path\n"
        )
        (rules_dir / "rule.yml").write_text(
            """
id: 92105
description: "filePath vs ProcessfilePath keys and values"
action: "BLOCK_EVENT"
events: [CHMOD]
detection:
    sel:
        filePath|startswith: /var
        ProcessfilePath|contains: bin
        process.cmd: "fooProcessfilePathbar"
        process.file.filename|fieldref: ProcessfilePath
    condition: sel
"""
        )
        rules = load_sigma_rules(
            str(rules_dir), field_mapping=load_field_mapping_file(str(map_path))
        )
        assert rules[0].detection["sel"] == {
            "process.file.path|startswith": "/var",
            "parent_process.file.path|contains": "bin",
            "process.cmd": "fooProcessfilePathbar",
            "process.file.filename|fieldref": "parent_process.file.path",
        }
