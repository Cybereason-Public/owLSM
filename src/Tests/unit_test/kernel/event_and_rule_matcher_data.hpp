#pragma once
#include <string>
#include <cstdio>
#include "events_structs.h"

namespace test_data {

constexpr const char* AND_OPERATORS_JSON = R"({
  "id_to_string": {
    "0": {"value": "/tmp/", "string_type": 0},
    "1": {"value": "test", "string_type": 1},
    "2": {"value": "/var/", "string_type": 1},
    "3": {"value": "/usr/bin/", "string_type": 0},
    "4": {"value": "bash", "string_type": 1},
    "5": {"value": "/home/", "string_type": 0},
    "6": {"value": ".bak", "string_type": 1},
    "7": {"value": "mv", "string_type": 0},
    "8": {"value": ".log", "string_type": 0},
    "9": {"value": "/usr/", "string_type": 1}
  },
  "id_to_predicate": {
    "0": {"field": "target.file.path", "comparison_type": "startswith", "string_idx": 0, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "1": {"field": "target.file.mode", "comparison_type": "above", "string_idx": -1, "numerical_value": 384, "fieldref": "FIELD_TYPE_NONE"},
    "2": {"field": "process.ruid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "3": {"field": "process.file.filename", "comparison_type": "contains", "string_idx": 1, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "4": {"field": "target.file.path", "comparison_type": "contains", "string_idx": 2, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "5": {"field": "target.file.owner.uid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 0, "fieldref": "FIELD_TYPE_NONE"},
    "6": {"field": "process.euid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 0, "fieldref": "FIELD_TYPE_NONE"},
    "7": {"field": "process.file.path", "comparison_type": "startswith", "string_idx": 3, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "8": {"field": "target.process.file.path", "comparison_type": "startswith", "string_idx": 0, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "9": {"field": "target.process.ruid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "10": {"field": "process.ppid", "comparison_type": "above", "string_idx": -1, "numerical_value": 1, "fieldref": "FIELD_TYPE_NONE"},
    "11": {"field": "process.file.filename", "comparison_type": "contains", "string_idx": 4, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "12": {"field": "rename.source_file.path", "comparison_type": "startswith", "string_idx": 5, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "13": {"field": "rename.destination_file.path", "comparison_type": "contains", "string_idx": 6, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "14": {"field": "process.pid", "comparison_type": "above", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "15": {"field": "process.file.filename", "comparison_type": "exactmatch", "string_idx": 7, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "16": {"field": "target.file.path", "comparison_type": "endswith", "string_idx": 8, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "17": {"field": "target.file.mode", "comparison_type": "below", "string_idx": -1, "numerical_value": 448, "fieldref": "FIELD_TYPE_NONE"},
    "18": {"field": "process.euid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "19": {"field": "process.file.path", "comparison_type": "contains", "string_idx": 9, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"}
  },
  "rules": [
    {
      "id": 1001,
      "description": "Test CHMOD with AND operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHMOD"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 1},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 2},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 3},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"}
      ]
    },
    {
      "id": 1002,
      "description": "Test CHOWN with AND operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHOWN"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 4},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 5},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 6},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 7},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"}
      ]
    },
    {
      "id": 1004,
      "description": "Test EXEC with AND operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 8},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 9},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 10},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 11},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"}
      ]
    },
    {
      "id": 1003,
      "description": "Test RENAME with AND operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["RENAME"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 12},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 13},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 14},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 15},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"}
      ]
    },
    {
      "id": 1005,
      "description": "Test WRITE with AND operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["WRITE"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 16},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 17},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 18},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 19},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"}
      ]
    }
  ]
})";

// ============================================================================
// TEST EVENTS - MATCHING CASES
// ============================================================================

// Event that SHOULD match CHMOD rule (1001)
// Rule requires: path starts with "/tmp/", mode > 0600, ruid == 1000, filename contains "test"
inline event_t create_chmod_matching_event() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Target file
    strncpy(event.data.chmod.file.path.value, "/tmp/testfile.txt", PATH_MAX);
    event.data.chmod.file.path.length = strlen("/tmp/testfile.txt");
    event.data.chmod.file.mode = 666;
    event.data.chmod.requested_mode = 777;
    
    // Process
    event.process.ruid = 1000;
    strncpy(event.process.file.filename.value, "testfile.txt", CMD_MAX);
    event.process.file.filename.length = strlen("testfile.txt");
    
    return event;
}

// Event that SHOULD match CHOWN rule (1002)
// Rule requires: path contains "/var/", owner_uid == 0, euid == 0, process path starts with "/usr/bin/"
inline event_t create_chown_matching_event() {
    event_t event = {};
    event.type = CHOWN;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Target file
    strncpy(event.data.chown.file.path.value, "/var/log/syslog", PATH_MAX);
    event.data.chown.file.path.length = strlen("/var/log/syslog");
    event.data.chown.file.owner.uid = 0;
    
    // Process
    event.process.euid = 0;
    strncpy(event.process.file.path.value, "/usr/bin/chown", PATH_MAX);
    event.process.file.path.length = strlen("/usr/bin/chown");
    
    return event;
}

// Event that SHOULD match EXEC rule (1004)
// Rule requires: target process path starts with "/tmp/", target ruid == 1000, ppid > 1, filename contains "bash"
inline event_t create_exec_matching_event() {
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Target process (new process being executed)
    strncpy(event.data.exec.new_process.file.path.value, "/tmp/malicious_script", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/tmp/malicious_script");
    event.data.exec.new_process.ruid = 1000;
    
    // Parent process
    event.process.ppid = 100;  // > 1
    strncpy(event.process.file.filename.value, "bash", CMD_MAX);
    event.process.file.filename.length = strlen("bash");
    
    return event;
}

// Event that SHOULD match RENAME rule (1003)
// Rule requires: source starts with "/home/", dest contains ".bak", pid > 1000, filename == "mv"
inline event_t create_rename_matching_event() {
    event_t event = {};
    event.type = RENAME;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Source file
    strncpy(event.data.rename.source_file.path.value, "/home/user/document.txt", PATH_MAX);
    event.data.rename.source_file.path.length = strlen("/home/user/document.txt");
    
    // Destination file
    strncpy(event.data.rename.destination_file.path.value, "/home/user/document.txt.bak", PATH_MAX);
    event.data.rename.destination_file.path.length = strlen("/home/user/document.txt.bak");
    
    // Process
    event.process.pid = 2000;  // > 1000
    strncpy(event.process.file.filename.value, "mv", FILENAME_MAX_LENGTH);
    event.process.file.filename.length = strlen("mv");
    
    return event;
}

// Event that SHOULD match WRITE rule (1005)
// Rule requires: path ends with ".log", mode < 0700, euid == 1000, process path contains "/usr/"
inline event_t create_write_matching_event() {
    event_t event = {};
    event.type = WRITE;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Target file
    strncpy(event.data.write.file.path.value, "/var/log/application.log", PATH_MAX);
    event.data.write.file.path.length = strlen("/var/log/application.log");
    event.data.write.file.mode = 0644;  // < 0700
    
    // Process
    event.process.euid = 1000;
    strncpy(event.process.file.path.value, "/usr/bin/logger", PATH_MAX);
    event.process.file.path.length = strlen("/usr/bin/logger");
    
    return event;
}

// ============================================================================
// TEST EVENTS - NON-MATCHING CASES
// ============================================================================

// Event that should NOT match CHMOD rule (fails ruid check)
inline event_t create_chmod_non_matching_event() {
    event_t event = create_chmod_matching_event();
    event.process.ruid = 999;  // Changed from 1000 to 999
    return event;
}

// Event that should NOT match CHOWN rule (fails path check)
inline event_t create_chown_non_matching_event() {
    event_t event = create_chown_matching_event();
    strncpy(event.data.chown.file.path.value, "/tmp/file", PATH_MAX);  // Changed from "/var/" to "/tmp/"
    event.data.chown.file.path.length = strlen("/tmp/file");
    return event;
}

// Event that should NOT match EXEC rule (fails ppid check)
inline event_t create_exec_non_matching_event() {
    event_t event = create_exec_matching_event();
    event.process.ppid = 1;  // Changed from 100 to 1 (not > 1)
    return event;
}

// Event that should NOT match RENAME rule (fails filename check)
inline event_t create_rename_non_matching_event() {
    event_t event = create_rename_matching_event();
    strncpy(event.process.file.filename.value, "cp", CMD_MAX);  // Changed from "mv" to "cp"
    event.process.file.filename.length = strlen("cp");
    return event;
}

// Event that should NOT match WRITE rule (fails mode check)
inline event_t create_write_non_matching_event() {
    event_t event = create_write_matching_event();
    event.data.write.file.mode = 0755;  // Changed from 0644 to 0755 (not < 0700)
    return event;
}

// ============================================================================
// OR OPERATORS JSON
// ============================================================================
constexpr const char* OR_OPERATORS_JSON = R"({
  "id_to_string": {
    "0": {"value": "/tmp/", "string_type": 0},
    "1": {"value": "chmod", "string_type": 1},
    "2": {"value": "/var/", "string_type": 1},
    "3": {"value": "/usr/bin/", "string_type": 0},
    "4": {"value": "bash", "string_type": 1},
    "5": {"value": "/home/", "string_type": 0},
    "6": {"value": ".bak", "string_type": 1},
    "7": {"value": "mv", "string_type": 0},
    "8": {"value": ".log", "string_type": 0},
    "9": {"value": "/usr/", "string_type": 1}
  },
  "id_to_predicate": {
    "0": {"field": "target.file.path", "comparison_type": "startswith", "string_idx": 0, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "1": {"field": "target.file.mode", "comparison_type": "above", "string_idx": -1, "numerical_value": 493, "fieldref": "FIELD_TYPE_NONE"},
    "2": {"field": "process.ruid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "3": {"field": "process.file.filename", "comparison_type": "contains", "string_idx": 1, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "4": {"field": "target.file.path", "comparison_type": "contains", "string_idx": 2, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "5": {"field": "target.file.owner.uid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 0, "fieldref": "FIELD_TYPE_NONE"},
    "6": {"field": "process.euid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 0, "fieldref": "FIELD_TYPE_NONE"},
    "7": {"field": "process.file.path", "comparison_type": "startswith", "string_idx": 3, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "8": {"field": "target.process.file.path", "comparison_type": "startswith", "string_idx": 0, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "9": {"field": "target.process.ruid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "10": {"field": "process.ppid", "comparison_type": "above", "string_idx": -1, "numerical_value": 1, "fieldref": "FIELD_TYPE_NONE"},
    "11": {"field": "process.file.filename", "comparison_type": "contains", "string_idx": 4, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "12": {"field": "rename.source_file.path", "comparison_type": "startswith", "string_idx": 5, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "13": {"field": "rename.destination_file.path", "comparison_type": "contains", "string_idx": 6, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "14": {"field": "process.pid", "comparison_type": "above", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "15": {"field": "process.file.filename", "comparison_type": "exactmatch", "string_idx": 7, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "16": {"field": "target.file.path", "comparison_type": "endswith", "string_idx": 8, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "17": {"field": "target.file.mode", "comparison_type": "below", "string_idx": -1, "numerical_value": 448, "fieldref": "FIELD_TYPE_NONE"},
    "18": {"field": "process.euid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "19": {"field": "process.file.path", "comparison_type": "contains", "string_idx": 9, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"}
  },
  "rules": [
    {
      "id": 2001,
      "description": "Test CHMOD with OR operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHMOD"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 1},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 2},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 3},
        {"operator_type": "OPERATOR_OR"},
        {"operator_type": "OPERATOR_OR"},
        {"operator_type": "OPERATOR_OR"}
      ]
    },
    {
      "id": 2002,
      "description": "Test CHOWN with OR operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHOWN"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 4},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 5},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 6},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 7},
        {"operator_type": "OPERATOR_OR"},
        {"operator_type": "OPERATOR_OR"},
        {"operator_type": "OPERATOR_OR"}
      ]
    },
    {
      "id": 2003,
      "description": "Test EXEC with OR operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 8},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 9},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 10},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 11},
        {"operator_type": "OPERATOR_OR"},
        {"operator_type": "OPERATOR_OR"},
        {"operator_type": "OPERATOR_OR"}
      ]
    },
    {
      "id": 2004,
      "description": "Test RENAME with OR operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["RENAME"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 12},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 13},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 14},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 15},
        {"operator_type": "OPERATOR_OR"},
        {"operator_type": "OPERATOR_OR"},
        {"operator_type": "OPERATOR_OR"}
      ]
    },
    {
      "id": 2005,
      "description": "Test WRITE with OR operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["WRITE"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 16},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 17},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 18},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 19},
        {"operator_type": "OPERATOR_OR"},
        {"operator_type": "OPERATOR_OR"},
        {"operator_type": "OPERATOR_OR"}
      ]
    }
  ]
})";

// ============================================================================
// NOT OPERATORS JSON
// ============================================================================
constexpr const char* NOT_OPERATORS_JSON = R"({
  "id_to_string": {
    "0": {"value": "/tmp/", "string_type": 0},
    "1": {"value": "chmod", "string_type": 1},
    "2": {"value": "/var/", "string_type": 1},
    "3": {"value": "/usr/bin/", "string_type": 0},
    "4": {"value": "bash", "string_type": 1},
    "5": {"value": "/home/", "string_type": 0},
    "6": {"value": ".bak", "string_type": 1},
    "7": {"value": "mv", "string_type": 0},
    "8": {"value": ".log", "string_type": 0},
    "9": {"value": "/usr/", "string_type": 1}
  },
  "id_to_predicate": {
    "0": {"field": "target.file.path", "comparison_type": "startswith", "string_idx": 0, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "1": {"field": "target.file.mode", "comparison_type": "above", "string_idx": -1, "numerical_value": 493, "fieldref": "FIELD_TYPE_NONE"},
    "2": {"field": "process.ruid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "3": {"field": "process.file.filename", "comparison_type": "contains", "string_idx": 1, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "4": {"field": "target.file.path", "comparison_type": "contains", "string_idx": 2, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "5": {"field": "target.file.owner.uid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 0, "fieldref": "FIELD_TYPE_NONE"},
    "6": {"field": "process.euid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 0, "fieldref": "FIELD_TYPE_NONE"},
    "7": {"field": "process.file.path", "comparison_type": "startswith", "string_idx": 3, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "8": {"field": "target.process.file.path", "comparison_type": "startswith", "string_idx": 0, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "9": {"field": "target.process.ruid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "10": {"field": "process.ppid", "comparison_type": "above", "string_idx": -1, "numerical_value": 1, "fieldref": "FIELD_TYPE_NONE"},
    "11": {"field": "process.file.filename", "comparison_type": "contains", "string_idx": 4, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "12": {"field": "rename.source_file.path", "comparison_type": "startswith", "string_idx": 5, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "13": {"field": "rename.destination_file.path", "comparison_type": "contains", "string_idx": 6, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "14": {"field": "process.pid", "comparison_type": "above", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "15": {"field": "process.file.filename", "comparison_type": "exactmatch", "string_idx": 7, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "16": {"field": "target.file.path", "comparison_type": "endswith", "string_idx": 8, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "17": {"field": "target.file.mode", "comparison_type": "below", "string_idx": -1, "numerical_value": 448, "fieldref": "FIELD_TYPE_NONE"},
    "18": {"field": "process.euid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "19": {"field": "process.file.path", "comparison_type": "contains", "string_idx": 9, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"}
  },
  "rules": [
    {
      "id": 3001,
      "description": "Test CHMOD with NOT operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHMOD"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 1},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 2},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 3},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_NOT"}
      ]
    },
    {
      "id": 3002,
      "description": "Test CHOWN with NOT operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHOWN"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 4},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 5},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 6},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 7},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_NOT"}
      ]
    },
    {
      "id": 3003,
      "description": "Test EXEC with NOT operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 8},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 9},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 10},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 11},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_NOT"}
      ]
    },
    {
      "id": 3004,
      "description": "Test RENAME with NOT operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["RENAME"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 12},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 13},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 14},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 15},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_NOT"}
      ]
    },
    {
      "id": 3005,
      "description": "Test WRITE with NOT operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["WRITE"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 16},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 17},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 18},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 19},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_NOT"}
      ]
    }
  ]
})";

// ============================================================================
// OR OPERATORS TEST EVENTS - MATCHING CASES
// (Only ONE condition needs to be true for a match)
// ============================================================================

// Event that SHOULD match CHMOD OR rule (2001) - matches via ruid == 1000
// Conditions: path starts with "/tmp/" OR mode > 0755 OR ruid == 1000 OR filename contains "chmod"
inline event_t create_chmod_or_matching_event() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Target file - NOT matching first two conditions
    strncpy(event.data.chmod.file.path.value, "/var/file.txt", PATH_MAX);
    event.data.chmod.file.path.length = strlen("/var/file.txt");
    event.data.chmod.file.mode = 0644;  // Not > 0755
    
    // Process - ruid matches (1000)
    event.process.ruid = 1000;
    strncpy(event.process.file.filename.value, "myapp", CMD_MAX);
    event.process.file.filename.length = strlen("myapp");  // Not containing "chmod"
    
    return event;
}

// Event that SHOULD match CHOWN OR rule (2002) - matches via path contains "/var/"
// Conditions: path contains "/var/" OR owner_uid == 0 OR euid == 0 OR process path starts with "/usr/bin/"
inline event_t create_chown_or_matching_event() {
    event_t event = {};
    event.type = CHOWN;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Target file - path contains "/var/"
    strncpy(event.data.chown.file.path.value, "/var/log/syslog", PATH_MAX);
    event.data.chown.file.path.length = strlen("/var/log/syslog");
    event.data.chown.file.owner.uid = 100;  // Not 0
    
    // Process - not matching other conditions
    event.process.euid = 1000;  // Not 0
    strncpy(event.process.file.path.value, "/home/user/myapp", PATH_MAX);
    event.process.file.path.length = strlen("/home/user/myapp");  // Not starting with "/usr/bin/"
    
    return event;
}

// Event that SHOULD match EXEC OR rule (2003) - matches via ppid > 1
// Conditions: target path starts with "/tmp/" OR target ruid == 1000 OR ppid > 1 OR filename contains "bash"
inline event_t create_exec_or_matching_event() {
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Target process - not matching first two conditions
    strncpy(event.data.exec.new_process.file.path.value, "/usr/bin/ls", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/usr/bin/ls");
    event.data.exec.new_process.ruid = 0;  // Not 1000
    
    // Parent process - ppid > 1 matches
    event.process.ppid = 100;
    strncpy(event.process.file.filename.value, "zsh", CMD_MAX);
    event.process.file.filename.length = strlen("zsh");  // Not containing "bash"
    
    return event;
}

// Event that SHOULD match RENAME OR rule (2004) - matches via source starts with "/home/"
// Conditions: source starts with "/home/" OR dest contains ".bak" OR pid > 1000 OR filename == "mv"
inline event_t create_rename_or_matching_event() {
    event_t event = {};
    event.type = RENAME;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Source file - starts with "/home/"
    strncpy(event.data.rename.source_file.path.value, "/home/user/file.txt", PATH_MAX);
    event.data.rename.source_file.path.length = strlen("/home/user/file.txt");
    
    // Destination file - not containing ".bak"
    strncpy(event.data.rename.destination_file.path.value, "/home/user/file_new.txt", PATH_MAX);
    event.data.rename.destination_file.path.length = strlen("/home/user/file_new.txt");
    
    // Process - not matching other conditions
    event.process.pid = 500;  // Not > 1000
    strncpy(event.process.file.filename.value, "cp", CMD_MAX);
    event.process.file.filename.length = strlen("cp");  // Not "mv"
    
    return event;
}

// Event that SHOULD match WRITE OR rule (2005) - matches via path ends with ".log"
// Conditions: path ends with ".log" OR mode < 0700 OR euid == 1000 OR process path contains "/usr/"
inline event_t create_write_or_matching_event() {
    event_t event = {};
    event.type = WRITE;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Target file - ends with ".log"
    strncpy(event.data.write.file.path.value, "/var/log/application.log", PATH_MAX);
    event.data.write.file.path.length = strlen("/var/log/application.log");
    event.data.write.file.mode = 0755;  // Not < 0700
    
    // Process - not matching other conditions
    event.process.euid = 0;  // Not 1000
    strncpy(event.process.file.path.value, "/home/user/myapp", PATH_MAX);
    event.process.file.path.length = strlen("/home/user/myapp");  // Not containing "/usr/"
    
    return event;
}

// ============================================================================
// OR OPERATORS TEST EVENTS - NON-MATCHING CASES
// (ALL conditions must be false for a non-match)
// ============================================================================

// Event that should NOT match CHMOD OR rule - all conditions false
inline event_t create_chmod_or_non_matching_event() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Not starting with "/tmp/"
    strncpy(event.data.chmod.file.path.value, "/var/file.txt", PATH_MAX);
    event.data.chmod.file.path.length = strlen("/var/file.txt");
    event.data.chmod.file.mode = 0644;  // Not > 0755
    
    event.process.ruid = 0;  // Not 1000
    strncpy(event.process.file.filename.value, "myapp", CMD_MAX);
    event.process.file.filename.length = strlen("myapp");  // Not containing "chmod"
    
    return event;
}

// Event that should NOT match CHOWN OR rule - all conditions false
inline event_t create_chown_or_non_matching_event() {
    event_t event = {};
    event.type = CHOWN;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Not containing "/var/"
    strncpy(event.data.chown.file.path.value, "/tmp/file.txt", PATH_MAX);
    event.data.chown.file.path.length = strlen("/tmp/file.txt");
    event.data.chown.file.owner.uid = 100;  // Not 0
    
    event.process.euid = 1000;  // Not 0
    strncpy(event.process.file.path.value, "/home/user/myapp", PATH_MAX);
    event.process.file.path.length = strlen("/home/user/myapp");  // Not starting with "/usr/bin/"
    
    return event;
}

// Event that should NOT match EXEC OR rule - all conditions false
inline event_t create_exec_or_non_matching_event() {
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Not starting with "/tmp/"
    strncpy(event.data.exec.new_process.file.path.value, "/usr/bin/ls", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/usr/bin/ls");
    event.data.exec.new_process.ruid = 0;  // Not 1000
    
    event.process.ppid = 1;  // Not > 1
    strncpy(event.process.file.filename.value, "zsh", CMD_MAX);
    event.process.file.filename.length = strlen("zsh");  // Not containing "bash"
    
    return event;
}

// Event that should NOT match RENAME OR rule - all conditions false
inline event_t create_rename_or_non_matching_event() {
    event_t event = {};
    event.type = RENAME;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Not starting with "/home/"
    strncpy(event.data.rename.source_file.path.value, "/tmp/file.txt", PATH_MAX);
    event.data.rename.source_file.path.length = strlen("/tmp/file.txt");
    
    // Not containing ".bak"
    strncpy(event.data.rename.destination_file.path.value, "/tmp/file_new.txt", PATH_MAX);
    event.data.rename.destination_file.path.length = strlen("/tmp/file_new.txt");
    
    event.process.pid = 500;  // Not > 1000
    strncpy(event.process.file.filename.value, "cp", CMD_MAX);
    event.process.file.filename.length = strlen("cp");  // Not "mv"
    
    return event;
}

// Event that should NOT match WRITE OR rule - all conditions false
inline event_t create_write_or_non_matching_event() {
    event_t event = {};
    event.type = WRITE;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // Not ending with ".log"
    strncpy(event.data.write.file.path.value, "/var/data/file.txt", PATH_MAX);
    event.data.write.file.path.length = strlen("/var/data/file.txt");
    event.data.write.file.mode = 0755;  // Not < 0700
    
    event.process.euid = 0;  // Not 1000
    strncpy(event.process.file.path.value, "/home/user/myapp", PATH_MAX);
    event.process.file.path.length = strlen("/home/user/myapp");  // Not containing "/usr/"
    
    return event;
}

// ============================================================================
// NOT OPERATORS TEST EVENTS - MATCHING CASES
// Rule matches when NOT(all conditions in exclusion are true)
// i.e., at least one condition in the exclusion must be false
// ============================================================================

// Event that SHOULD match CHMOD NOT rule (3001) - exclusion is false because ruid != 1000
// Exclusion: path starts with "/tmp/" AND mode > 0755 AND ruid == 1000 AND filename contains "chmod"
inline event_t create_chmod_not_matching_event() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // These conditions ARE true
    strncpy(event.data.chmod.file.path.value, "/tmp/file.txt", PATH_MAX);
    event.data.chmod.file.path.length = strlen("/tmp/file.txt");
    event.data.chmod.file.mode = 0777;  // > 0755
    
    // This condition is FALSE - breaks the exclusion
    event.process.ruid = 0;  // NOT 1000
    strncpy(event.process.file.filename.value, "mychmod", CMD_MAX);
    event.process.file.filename.length = strlen("mychmod");  // Contains "chmod"
    
    return event;
}

// Event that SHOULD match CHOWN NOT rule (3002) - exclusion is false because euid != 0
// Exclusion: path contains "/var/" AND owner_uid == 0 AND euid == 0 AND process path starts with "/usr/bin/"
inline event_t create_chown_not_matching_event() {
    event_t event = {};
    event.type = CHOWN;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    strncpy(event.data.chown.file.path.value, "/var/log/syslog", PATH_MAX);
    event.data.chown.file.path.length = strlen("/var/log/syslog");
    event.data.chown.file.owner.uid = 0;
    
    // This condition is FALSE - breaks the exclusion
    event.process.euid = 1000;  // NOT 0
    strncpy(event.process.file.path.value, "/usr/bin/chown", PATH_MAX);
    event.process.file.path.length = strlen("/usr/bin/chown");
    
    return event;
}

// Event that SHOULD match EXEC NOT rule (3003) - exclusion is false because target ruid != 1000
// Exclusion: target path starts with "/tmp/" AND target ruid == 1000 AND ppid > 1 AND filename contains "bash"
inline event_t create_exec_not_matching_event() {
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    strncpy(event.data.exec.new_process.file.path.value, "/tmp/script", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/tmp/script");
    // This condition is FALSE - breaks the exclusion
    event.data.exec.new_process.ruid = 0;  // NOT 1000
    
    event.process.ppid = 100;  // > 1
    strncpy(event.process.file.filename.value, "bash", CMD_MAX);
    event.process.file.filename.length = strlen("bash");
    
    return event;
}

// Event that SHOULD match RENAME NOT rule (3004) - exclusion is false because pid <= 1000
// Exclusion: source starts with "/home/" AND dest contains ".bak" AND pid > 1000 AND filename == "mv"
inline event_t create_rename_not_matching_event() {
    event_t event = {};
    event.type = RENAME;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    strncpy(event.data.rename.source_file.path.value, "/home/user/file.txt", PATH_MAX);
    event.data.rename.source_file.path.length = strlen("/home/user/file.txt");
    
    strncpy(event.data.rename.destination_file.path.value, "/home/user/file.bak", PATH_MAX);
    event.data.rename.destination_file.path.length = strlen("/home/user/file.bak");
    
    // This condition is FALSE - breaks the exclusion
    event.process.pid = 500;  // NOT > 1000
    strncpy(event.process.file.filename.value, "mv", FILENAME_MAX_LENGTH);
    event.process.file.filename.length = strlen("mv");
    
    return event;
}

// Event that SHOULD match WRITE NOT rule (3005) - exclusion is false because mode >= 0700
// Exclusion: path ends with ".log" AND mode < 0700 AND euid == 1000 AND process path contains "/usr/"
inline event_t create_write_not_matching_event() {
    event_t event = {};
    event.type = WRITE;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    strncpy(event.data.write.file.path.value, "/var/log/app.log", PATH_MAX);
    event.data.write.file.path.length = strlen("/var/log/app.log");
    // This condition is FALSE - breaks the exclusion
    event.data.write.file.mode = 0755;  // NOT < 0700
    
    event.process.euid = 1000;
    strncpy(event.process.file.path.value, "/usr/bin/logger", PATH_MAX);
    event.process.file.path.length = strlen("/usr/bin/logger");
    
    return event;
}

// ============================================================================
// NOT OPERATORS TEST EVENTS - NON-MATCHING CASES
// Rule does NOT match when the exclusion is true (all conditions are true)
// Because NOT(true) = false
// ============================================================================

// Event that should NOT match CHMOD NOT rule - all exclusion conditions are TRUE
inline event_t create_chmod_not_non_matching_event() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // All conditions TRUE
    strncpy(event.data.chmod.file.path.value, "/tmp/file.txt", PATH_MAX);
    event.data.chmod.file.path.length = strlen("/tmp/file.txt");
    event.data.chmod.file.mode = 0777;  // > 0755 (493)
    
    event.process.ruid = 1000;
    strncpy(event.process.file.filename.value, "mychmod", CMD_MAX);
    event.process.file.filename.length = strlen("mychmod");  // Contains "chmod"
    
    return event;
}

// Event that should NOT match CHOWN NOT rule - all exclusion conditions are TRUE
inline event_t create_chown_not_non_matching_event() {
    event_t event = {};
    event.type = CHOWN;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // All conditions TRUE
    strncpy(event.data.chown.file.path.value, "/var/log/syslog", PATH_MAX);
    event.data.chown.file.path.length = strlen("/var/log/syslog");
    event.data.chown.file.owner.uid = 0;
    
    event.process.euid = 0;
    strncpy(event.process.file.path.value, "/usr/bin/chown", PATH_MAX);
    event.process.file.path.length = strlen("/usr/bin/chown");
    
    return event;
}

// Event that should NOT match EXEC NOT rule - all exclusion conditions are TRUE
inline event_t create_exec_not_non_matching_event() {
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // All conditions TRUE
    strncpy(event.data.exec.new_process.file.path.value, "/tmp/script", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/tmp/script");
    event.data.exec.new_process.ruid = 1000;
    
    event.process.ppid = 100;  // > 1
    strncpy(event.process.file.filename.value, "bash", CMD_MAX);
    event.process.file.filename.length = strlen("bash");
    
    return event;
}

// Event that should NOT match RENAME NOT rule - all exclusion conditions are TRUE
inline event_t create_rename_not_non_matching_event() {
    event_t event = {};
    event.type = RENAME;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // All conditions TRUE
    strncpy(event.data.rename.source_file.path.value, "/home/user/file.txt", PATH_MAX);
    event.data.rename.source_file.path.length = strlen("/home/user/file.txt");
    
    strncpy(event.data.rename.destination_file.path.value, "/home/user/file.bak", PATH_MAX);
    event.data.rename.destination_file.path.length = strlen("/home/user/file.bak");
    
    event.process.pid = 2000;  // > 1000
    strncpy(event.process.file.filename.value, "mv", FILENAME_MAX_LENGTH);
    event.process.file.filename.length = strlen("mv");
    
    return event;
}

// Event that should NOT match WRITE NOT rule - all exclusion conditions are TRUE
inline event_t create_write_not_non_matching_event() {
    event_t event = {};
    event.type = WRITE;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // All conditions TRUE
    strncpy(event.data.write.file.path.value, "/var/log/app.log", PATH_MAX);
    event.data.write.file.path.length = strlen("/var/log/app.log");
    event.data.write.file.mode = 0644;  // < 0700 (448)
    
    event.process.euid = 1000;
    strncpy(event.process.file.path.value, "/usr/bin/logger", PATH_MAX);
    event.process.file.path.length = strlen("/usr/bin/logger");
    
    return event;
}

// ============================================================================
// COMPLEX OPERATORS JSON (AND, OR, NOT combined)
// ============================================================================
constexpr const char* COMPLEX_OPERATORS_JSON = R"({
  "id_to_string": {
    "0": {"value": "/tmp/", "string_type": 0},
    "1": {"value": "bash", "string_type": 1},
    "2": {"value": "safe", "string_type": 1},
    "3": {"value": "/home/", "string_type": 0},
    "4": {"value": ".bak", "string_type": 1},
    "5": {"value": "mv", "string_type": 0},
    "6": {"value": "protected", "string_type": 1}
  },
  "id_to_predicate": {
    "0": {"field": "target.process.file.path", "comparison_type": "startswith", "string_idx": 0, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "1": {"field": "target.process.ruid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "2": {"field": "process.ppid", "comparison_type": "above", "string_idx": -1, "numerical_value": 1, "fieldref": "FIELD_TYPE_NONE"},
    "3": {"field": "process.file.filename", "comparison_type": "contains", "string_idx": 1, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "4": {"field": "process.euid", "comparison_type": "equal", "string_idx": -1, "numerical_value": 0, "fieldref": "FIELD_TYPE_NONE"},
    "5": {"field": "target.process.file.path", "comparison_type": "contains", "string_idx": 2, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "6": {"field": "rename.source_file.path", "comparison_type": "startswith", "string_idx": 3, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "7": {"field": "rename.destination_file.path", "comparison_type": "contains", "string_idx": 4, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "8": {"field": "process.pid", "comparison_type": "above", "string_idx": -1, "numerical_value": 1000, "fieldref": "FIELD_TYPE_NONE"},
    "9": {"field": "process.file.filename", "comparison_type": "exactmatch", "string_idx": 5, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "10": {"field": "rename.source_file.path", "comparison_type": "contains", "string_idx": 6, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"}
  },
  "rules": [
    {
      "id": 4001,
      "description": "Test EXEC with complex AND/OR/NOT operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 1},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 2},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 3},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_OR"},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 4},
        {"operator_type": "OPERATOR_NOT"},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 5},
        {"operator_type": "OPERATOR_NOT"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"}
      ]
    },
    {
      "id": 4002,
      "description": "Test RENAME with complex AND/OR/NOT operators",
      "action": "BLOCK_EVENT",
      "applied_events": ["RENAME"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 6},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 7},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 8},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 9},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_OR"},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 4},
        {"operator_type": "OPERATOR_NOT"},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 10},
        {"operator_type": "OPERATOR_NOT"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"}
      ]
    }
  ]
})";

// ============================================================================
// COMPLEX OPERATORS TEST EVENTS - EXEC
// Condition: ((sel1 AND sel2) OR (sel3 AND sel4)) AND NOT excl1 AND NOT excl2
// sel1: target path starts with "/tmp/"
// sel2: target ruid == 1000
// sel3: ppid > 1
// sel4: filename contains "bash"
// excl1: euid == 0 (must be false for match)
// excl2: target path contains "safe" (must be false for match)
// ============================================================================

// Match via first AND group (sel1 AND sel2), exclusions are false
inline event_t create_exec_complex_matching_via_first_group() {
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // sel1 TRUE: target path starts with "/tmp/"
    strncpy(event.data.exec.new_process.file.path.value, "/tmp/script.sh", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/tmp/script.sh");
    // sel2 TRUE: target ruid == 1000
    event.data.exec.new_process.ruid = 1000;
    
    // sel3 and sel4 can be false (we match via first group)
    event.process.ppid = 1;  // NOT > 1
    strncpy(event.process.file.filename.value, "zsh", CMD_MAX);
    event.process.file.filename.length = strlen("zsh");  // Not containing "bash"
    
    // excl1 FALSE: euid != 0
    event.process.euid = 1000;
    
    return event;
}

// Match via second AND group (sel3 AND sel4), exclusions are false
inline event_t create_exec_complex_matching_via_second_group() {
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // sel1 and sel2 can be false (we match via second group)
    strncpy(event.data.exec.new_process.file.path.value, "/usr/bin/ls", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/usr/bin/ls");  // Not starting with "/tmp/"
    event.data.exec.new_process.ruid = 0;  // Not 1000
    
    // sel3 TRUE: ppid > 1
    event.process.ppid = 100;
    // sel4 TRUE: filename contains "bash"
    strncpy(event.process.file.filename.value, "bash", CMD_MAX);
    event.process.file.filename.length = strlen("bash");
    
    // excl1 FALSE: euid != 0
    event.process.euid = 1000;
    
    return event;
}

// No match: first exclusion is true (euid == 0)
inline event_t create_exec_complex_non_matching_excl1_true() {
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // sel1 AND sel2 TRUE
    strncpy(event.data.exec.new_process.file.path.value, "/tmp/script.sh", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/tmp/script.sh");
    event.data.exec.new_process.ruid = 1000;
    
    event.process.ppid = 100;
    strncpy(event.process.file.filename.value, "bash", CMD_MAX);
    event.process.file.filename.length = strlen("bash");
    
    // excl1 TRUE: euid == 0, so NOT excl1 = false, rule doesn't match
    event.process.euid = 0;
    
    return event;
}

// No match: second exclusion is true (path contains "safe")
inline event_t create_exec_complex_non_matching_excl2_true() {
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // sel1 AND sel2 TRUE, but path contains "safe"
    strncpy(event.data.exec.new_process.file.path.value, "/tmp/safe_script.sh", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/tmp/safe_script.sh");
    event.data.exec.new_process.ruid = 1000;
    
    event.process.ppid = 100;
    strncpy(event.process.file.filename.value, "bash", CMD_MAX);
    event.process.file.filename.length = strlen("bash");
    
    // excl1 FALSE
    event.process.euid = 1000;
    // excl2 TRUE: path contains "safe", so NOT excl2 = false
    
    return event;
}

// No match: neither AND group is true
inline event_t create_exec_complex_non_matching_no_groups() {
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // sel1 FALSE: path doesn't start with "/tmp/"
    strncpy(event.data.exec.new_process.file.path.value, "/usr/bin/ls", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/usr/bin/ls");
    // sel2 FALSE: ruid != 1000
    event.data.exec.new_process.ruid = 0;
    
    // sel3 FALSE: ppid not > 1
    event.process.ppid = 1;
    // sel4 FALSE: filename doesn't contain "bash"
    strncpy(event.process.file.filename.value, "zsh", CMD_MAX);
    event.process.file.filename.length = strlen("zsh");
    
    // Exclusions are false (but doesn't matter since OR part is false)
    event.process.euid = 1000;
    
    return event;
}

// ============================================================================
// COMPLEX OPERATORS TEST EVENTS - RENAME
// Condition: ((sel1 AND sel2) OR (sel3 AND sel4)) AND NOT excl1 AND NOT excl2
// sel1: source starts with "/home/"
// sel2: dest contains ".bak"
// sel3: pid > 1000
// sel4: filename == "mv"
// excl1: euid == 0 (must be false for match)
// excl2: source contains "protected" (must be false for match)
// ============================================================================

// Match via first AND group (sel1 AND sel2), exclusions are false
inline event_t create_rename_complex_matching_via_first_group() {
    event_t event = {};
    event.type = RENAME;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // sel1 TRUE: source starts with "/home/"
    strncpy(event.data.rename.source_file.path.value, "/home/user/doc.txt", PATH_MAX);
    event.data.rename.source_file.path.length = strlen("/home/user/doc.txt");
    // sel2 TRUE: dest contains ".bak"
    strncpy(event.data.rename.destination_file.path.value, "/home/user/doc.txt.bak", PATH_MAX);
    event.data.rename.destination_file.path.length = strlen("/home/user/doc.txt.bak");
    
    // sel3 and sel4 can be false
    event.process.pid = 500;  // NOT > 1000
    strncpy(event.process.file.filename.value, "cp", CMD_MAX);
    event.process.file.filename.length = strlen("cp");  // Not "mv"
    
    // excl1 FALSE: euid != 0
    event.process.euid = 1000;
    
    return event;
}

// Match via second AND group (sel3 AND sel4), exclusions are false
inline event_t create_rename_complex_matching_via_second_group() {
    event_t event = {};
    event.type = RENAME;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // sel1 and sel2 can be false
    strncpy(event.data.rename.source_file.path.value, "/tmp/file.txt", PATH_MAX);
    event.data.rename.source_file.path.length = strlen("/tmp/file.txt");  // Not starting with "/home/"
    strncpy(event.data.rename.destination_file.path.value, "/tmp/file_new.txt", PATH_MAX);
    event.data.rename.destination_file.path.length = strlen("/tmp/file_new.txt");  // Not containing ".bak"
    
    // sel3 TRUE: pid > 1000
    event.process.pid = 2000;
    // sel4 TRUE: filename == "mv"
    strncpy(event.process.file.filename.value, "mv", FILENAME_MAX_LENGTH);
    event.process.file.filename.length = strlen("mv");
    
    // excl1 FALSE: euid != 0
    event.process.euid = 1000;
    
    return event;
}

// No match: first exclusion is true (euid == 0)
inline event_t create_rename_complex_non_matching_excl1_true() {
    event_t event = {};
    event.type = RENAME;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // sel1 AND sel2 TRUE
    strncpy(event.data.rename.source_file.path.value, "/home/user/doc.txt", PATH_MAX);
    event.data.rename.source_file.path.length = strlen("/home/user/doc.txt");
    strncpy(event.data.rename.destination_file.path.value, "/home/user/doc.txt.bak", PATH_MAX);
    event.data.rename.destination_file.path.length = strlen("/home/user/doc.txt.bak");
    
    event.process.pid = 2000;
    strncpy(event.process.file.filename.value, "mv", FILENAME_MAX_LENGTH);
    event.process.file.filename.length = strlen("mv");
    
    // excl1 TRUE: euid == 0, so NOT excl1 = false
    event.process.euid = 0;
    
    return event;
}

// No match: second exclusion is true (source contains "protected")
inline event_t create_rename_complex_non_matching_excl2_true() {
    event_t event = {};
    event.type = RENAME;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // sel1 AND sel2 TRUE, but source contains "protected"
    strncpy(event.data.rename.source_file.path.value, "/home/user/protected_doc.txt", PATH_MAX);
    event.data.rename.source_file.path.length = strlen("/home/user/protected_doc.txt");
    strncpy(event.data.rename.destination_file.path.value, "/home/user/doc.txt.bak", PATH_MAX);
    event.data.rename.destination_file.path.length = strlen("/home/user/doc.txt.bak");
    
    event.process.pid = 2000;
    strncpy(event.process.file.filename.value, "mv", FILENAME_MAX_LENGTH);
    event.process.file.filename.length = strlen("mv");
    
    // excl1 FALSE
    event.process.euid = 1000;
    // excl2 TRUE: source contains "protected"
    
    return event;
}

// No match: neither AND group is true
inline event_t create_rename_complex_non_matching_no_groups() {
    event_t event = {};
    event.type = RENAME;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // sel1 FALSE: source doesn't start with "/home/"
    strncpy(event.data.rename.source_file.path.value, "/tmp/file.txt", PATH_MAX);
    event.data.rename.source_file.path.length = strlen("/tmp/file.txt");
    // sel2 FALSE: dest doesn't contain ".bak"
    strncpy(event.data.rename.destination_file.path.value, "/tmp/file_new.txt", PATH_MAX);
    event.data.rename.destination_file.path.length = strlen("/tmp/file_new.txt");
    
    // sel3 FALSE: pid not > 1000
    event.process.pid = 500;
    // sel4 FALSE: filename != "mv"
    strncpy(event.process.file.filename.value, "cp", CMD_MAX);
    event.process.file.filename.length = strlen("cp");
    
    // Exclusions are false (but doesn't matter)
    event.process.euid = 1000;
    
    return event;
}

// ============================================================================
// PREDICATES CACHE TEST
// Tests that predicates_results_cache overrides actual predicate evaluation
// Uses OR_OPERATORS_JSON CHMOD rule (2001) with predicates:
//   pred 0: target.file.path starts with "/tmp/"
//   pred 1: target.file.mode > 493 (0755)
//   pred 2: process.ruid == 1000
//   pred 3: process.file.filename contains "chmod"
// Condition: pred0 OR pred1 OR pred2 OR pred3
// ============================================================================

// Event that does NOT match ANY predicate in the CHMOD OR rule (2001)
// All predicates would evaluate to FALSE without cache
inline event_t create_chmod_cache_test_event() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 123456789;  // Specific time to match cache entries
    event.action = ALLOW_EVENT;
    
    // pred 0 FALSE: path does NOT start with "/tmp/"
    strncpy(event.data.chmod.file.path.value, "/var/notmp/file.txt", PATH_MAX);
    event.data.chmod.file.path.length = strlen("/var/notmp/file.txt");
    
    // pred 1 FALSE: mode is NOT > 493 (0755)
    event.data.chmod.file.mode = 0644;  // 420 < 493
    
    // pred 2 FALSE: ruid is NOT 1000
    event.process.ruid = 0;
    
    // pred 3 FALSE: filename does NOT contain "chmod"
    strncpy(event.process.file.filename.value, "myapp", CMD_MAX);
    event.process.file.filename.length = strlen("myapp");
    
    return event;
}

// Cache entry time must match event time (123456789)
constexpr unsigned long long CACHE_TEST_EVENT_TIME = 123456789;

// ============================================================================
// ALL FIELDS JSON - RENAME (all source_file and destination_file fields)
// Generated by Rules/RulesGenerator/main.py from Rules/TestRules/all_fields/
// ============================================================================
constexpr const char* ALL_FIELDS_RENAME_JSON = R"({
  "id_to_string": {
    "0": {
      "value": "/home/",
      "string_type": 0
    },
    "1": {
      "value": "doc",
      "string_type": 1
    },
    "2": {
      "value": ".bak",
      "string_type": 0
    },
    "3": {
      "value": "document.bak",
      "string_type": 0
    },
    "4": {
      "value": "mv",
      "string_type": 1
    },
    "5": {
      "value": "/usr/bin/",
      "string_type": 0
    }
  },
  "id_to_predicate": {
    "0": {
      "field": "rename.source_file.path",
      "comparison_type": "startswith",
      "string_idx": 0,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "1": {
      "field": "rename.source_file.filename",
      "comparison_type": "contains",
      "string_idx": 1,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "2": {
      "field": "rename.source_file.owner.uid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "3": {
      "field": "rename.source_file.owner.gid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "4": {
      "field": "rename.source_file.mode",
      "comparison_type": "above",
      "string_idx": -1,
      "numerical_value": 384,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "5": {
      "field": "rename.source_file.suid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "6": {
      "field": "rename.source_file.sgid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "7": {
      "field": "rename.source_file.nlink",
      "comparison_type": "equal_above",
      "string_idx": -1,
      "numerical_value": 1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "8": {
      "field": "rename.source_file.type",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 5,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "9": {
      "field": "rename.destination_file.path",
      "comparison_type": "endswith",
      "string_idx": 2,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "10": {
      "field": "rename.destination_file.filename",
      "comparison_type": "exactmatch",
      "string_idx": 3,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "11": {
      "field": "rename.destination_file.owner.uid",
      "comparison_type": "equal_below",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "12": {
      "field": "rename.destination_file.owner.gid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "13": {
      "field": "rename.destination_file.mode",
      "comparison_type": "below",
      "string_idx": -1,
      "numerical_value": 448,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "14": {
      "field": "rename.destination_file.suid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "15": {
      "field": "rename.destination_file.sgid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "16": {
      "field": "rename.destination_file.nlink",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "17": {
      "field": "rename.destination_file.type",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 5,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "18": {
      "field": "process.pid",
      "comparison_type": "above",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "19": {
      "field": "process.ruid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "20": {
      "field": "process.euid",
      "comparison_type": "equal_below",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "21": {
      "field": "process.cmd",
      "comparison_type": "contains",
      "string_idx": 4,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "22": {
      "field": "process.file.path",
      "comparison_type": "startswith",
      "string_idx": 5,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "23": {
      "field": "process.file.filename",
      "comparison_type": "exactmatch",
      "string_idx": 4,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "24": {
      "field": "process.file.type",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 5,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "rules": [
    {
      "id": 5001,
      "description": "Test RENAME with all source/dest file fields",
      "action": "BLOCK_EVENT",
      "applied_events": [
        "RENAME"
      ],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 1},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 2},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 3},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 4},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 5},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 6},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 7},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 8},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 9},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 10},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 11},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 12},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 13},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 14},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 15},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 16},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 17},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 18},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 19},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 20},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 21},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 22},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 23},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 24},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"}
      ]
    }
  ]
})";

// ============================================================================
// ALL FIELDS TEST EVENTS - RENAME
// Tests ALL source_file and destination_file fields (18 fields) plus process (7 fields)
// ============================================================================

// Event that SHOULD match RENAME ALL FIELDS rule (5001)
inline event_t create_rename_all_fields_matching_event() {
    event_t event = {};
    event.type = RENAME;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    
    // === SOURCE FILE (9 predicates) ===
    // pred 0: source path starts with "/home/"
    strncpy(event.data.rename.source_file.path.value, "/home/user/document.txt", PATH_MAX);
    event.data.rename.source_file.path.length = strlen("/home/user/document.txt");
    // pred 1: source filename contains "doc"
    strncpy(event.data.rename.source_file.filename.value, "document.txt", FILENAME_MAX_LENGTH);
    event.data.rename.source_file.filename.length = strlen("document.txt");
    // pred 2: source owner.uid == 1000
    event.data.rename.source_file.owner.uid = 1000;
    // pred 3: source owner.gid == 1000
    event.data.rename.source_file.owner.gid = 1000;
    // pred 4: source mode > 384 (0600)
    event.data.rename.source_file.mode = 0644;  // 420 > 384
    // pred 5: source suid == 0
    event.data.rename.source_file.suid = 0;
    // pred 6: source sgid == 0
    event.data.rename.source_file.sgid = 0;
    // pred 7: source nlink >= 1
    event.data.rename.source_file.nlink = 1;
    // pred 8: source type == 5 (REGULAR_FILE)
    event.data.rename.source_file.type = REGULAR_FILE;
    
    // === DESTINATION FILE (9 predicates) ===
    // pred 9: dest path ends with ".bak"
    strncpy(event.data.rename.destination_file.path.value, "/home/user/document.bak", PATH_MAX);
    event.data.rename.destination_file.path.length = strlen("/home/user/document.bak");
    // pred 10: dest filename == "document.bak"
    strncpy(event.data.rename.destination_file.filename.value, "document.bak", FILENAME_MAX_LENGTH);
    event.data.rename.destination_file.filename.length = strlen("document.bak");
    // pred 11: dest owner.uid <= 1000
    event.data.rename.destination_file.owner.uid = 1000;
    // pred 12: dest owner.gid == 1000
    event.data.rename.destination_file.owner.gid = 1000;
    // pred 13: dest mode < 448 (0700)
    event.data.rename.destination_file.mode = 0644;  // 420 < 448
    // pred 14: dest suid == 0
    event.data.rename.destination_file.suid = 0;
    // pred 15: dest sgid == 0
    event.data.rename.destination_file.sgid = 0;
    // pred 16: dest nlink == 1
    event.data.rename.destination_file.nlink = 1;
    // pred 17: dest type == 5 (REGULAR_FILE)
    event.data.rename.destination_file.type = REGULAR_FILE;
    
    // === PROCESS (7 predicates) ===
    // pred 18: pid > 1000
    event.process.pid = 2000;
    // pred 19: ruid == 1000
    event.process.ruid = 1000;
    // pred 20: euid <= 1000
    event.process.euid = 1000;
    // pred 21: cmd contains "mv"
    strncpy(event.process.cmd.value, "mv document.txt document.bak", CMD_MAX);
    event.process.cmd.length = strlen("mv document.txt document.bak");
    // pred 22: file path starts with "/usr/bin/"
    strncpy(event.process.file.path.value, "/usr/bin/mv", PATH_MAX);
    event.process.file.path.length = strlen("/usr/bin/mv");
    // pred 23: file filename == "mv"
    strncpy(event.process.file.filename.value, "mv", FILENAME_MAX_LENGTH);
    event.process.file.filename.length = strlen("mv");
    // pred 24: file type == 5 (REGULAR_FILE)
    event.process.file.type = REGULAR_FILE;
    
    return event;
}

// Event that should NOT match RENAME ALL FIELDS rule - fails source filename check only
inline event_t create_rename_all_fields_non_matching_event() {
    event_t event = create_rename_all_fields_matching_event();
    // Break pred 1: source filename doesn't contain "doc"
    strncpy(event.data.rename.source_file.filename.value, "myfile.txt", FILENAME_MAX_LENGTH);
    event.data.rename.source_file.filename.length = strlen("myfile.txt");
    return event;
}

// ============================================================================
// ALL FIELDS JSON - EXEC (all target.process/new_process fields + complex operators)
// Generated by Rules/RulesGenerator/main.py from Rules/TestRules/all_fields_exec/
// 61 tokens: 30 predicates, AND/OR/NOT operators
// ============================================================================
constexpr const char* ALL_FIELDS_EXEC_JSON = R"({
  "id_to_string": {
    "0": {
      "value": "script",
      "string_type": 1
    },
    "1": {
      "value": "/tmp/",
      "string_type": 0
    },
    "2": {
      "value": ".sh",
      "string_type": 0
    },
    "3": {
      "value": "/usr/",
      "string_type": 0
    },
    "4": {
      "value": "dangerous",
      "string_type": 1
    }
  },
  "id_to_predicate": {
    "0": {
      "field": "target.process.pid",
      "comparison_type": "above",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "1": {
      "field": "target.process.ppid",
      "comparison_type": "equal_above",
      "string_idx": -1,
      "numerical_value": 1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "2": {
      "field": "target.process.ruid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "3": {
      "field": "target.process.rgid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "4": {
      "field": "target.process.euid",
      "comparison_type": "equal_below",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "5": {
      "field": "target.process.egid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "6": {
      "field": "target.process.suid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "7": {
      "field": "target.process.cmd",
      "comparison_type": "contains",
      "string_idx": 0,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "8": {
      "field": "target.process.file.path",
      "comparison_type": "startswith",
      "string_idx": 1,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "9": {
      "field": "target.process.file.filename",
      "comparison_type": "endswith",
      "string_idx": 2,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "10": {
      "field": "target.process.file.owner.uid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "11": {
      "field": "target.process.file.owner.gid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "12": {
      "field": "target.process.file.mode",
      "comparison_type": "equal_above",
      "string_idx": -1,
      "numerical_value": 448,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "13": {
      "field": "target.process.file.suid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "14": {
      "field": "target.process.file.sgid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "15": {
      "field": "target.process.file.nlink",
      "comparison_type": "equal_above",
      "string_idx": -1,
      "numerical_value": 1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "16": {
      "field": "target.process.file.type",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 5,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "17": {
      "field": "process.pid",
      "comparison_type": "above",
      "string_idx": -1,
      "numerical_value": 100,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "18": {
      "field": "process.ppid",
      "comparison_type": "above",
      "string_idx": -1,
      "numerical_value": 1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "19": {
      "field": "process.ruid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "20": {
      "field": "process.euid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "21": {
      "field": "process.file.path",
      "comparison_type": "startswith",
      "string_idx": 3,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "22": {
      "field": "process.file.type",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 5,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "23": {
      "field": "parent_process.pid",
      "comparison_type": "above",
      "string_idx": -1,
      "numerical_value": 1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "24": {
      "field": "parent_process.ruid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "25": {
      "field": "parent_process.euid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 1000,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "26": {
      "field": "parent_process.file.path",
      "comparison_type": "startswith",
      "string_idx": 3,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "27": {
      "field": "parent_process.file.type",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 5,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "28": {
      "field": "process.euid",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    },
    "29": {
      "field": "target.process.file.path",
      "comparison_type": "contains",
      "string_idx": 4,
      "numerical_value": -1,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "rules": [
    {
      "id": 5002,
      "description": "Test EXEC with all new_process fields and complex operators",
      "action": "BLOCK_EVENT",
      "applied_events": [
        "EXEC"
      ],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 1},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 2},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 3},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 4},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 5},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 6},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 7},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 8},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 9},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 10},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 11},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 12},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 13},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 14},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 15},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 16},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 17},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 18},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 19},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 20},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 21},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 22},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 23},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 24},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 25},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 26},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 27},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_OR"},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 28},
        {"operator_type": "OPERATOR_NOT"},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 29},
        {"operator_type": "OPERATOR_NOT"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"}
      ]
    }
  ]
})";

// Event that should match EXEC ALL FIELDS rule (rule 5002)
// All 30 predicates evaluate to TRUE
inline event_t create_exec_all_fields_matching_event() {
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;

    // Target process (new_process) fields (predicates 0-16)
    // pred 0: target.process.pid > 0
    event.data.exec.new_process.pid = 1234;
    // pred 1: target.process.ppid >= 1
    event.data.exec.new_process.ppid = 100;
    // pred 2: target.process.ruid == 1000
    event.data.exec.new_process.ruid = 1000;
    // pred 3: target.process.rgid == 1000
    event.data.exec.new_process.rgid = 1000;
    // pred 4: target.process.euid <= 1000
    event.data.exec.new_process.euid = 1000;
    // pred 5: target.process.egid == 1000
    event.data.exec.new_process.egid = 1000;
    // pred 6: target.process.suid == 1000
    event.data.exec.new_process.suid = 1000;
    // pred 7: target.process.cmd contains "script"
    strncpy(event.data.exec.new_process.cmd.value, "/tmp/test_script.sh --arg1", CMD_MAX);
    event.data.exec.new_process.cmd.length = strlen("/tmp/test_script.sh --arg1");
    // pred 8: target.process.file.path startswith "/tmp/"
    strncpy(event.data.exec.new_process.file.path.value, "/tmp/test_script.sh", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/tmp/test_script.sh");
    // pred 9: target.process.file.filename endswith ".sh"
    strncpy(event.data.exec.new_process.file.filename.value, "test_script.sh", FILENAME_MAX_LENGTH);
    event.data.exec.new_process.file.filename.length = strlen("test_script.sh");
    // pred 10: target.process.file.owner.uid == 1000
    event.data.exec.new_process.file.owner.uid = 1000;
    // pred 11: target.process.file.owner.gid == 1000
    event.data.exec.new_process.file.owner.gid = 1000;
    // pred 12: target.process.file.mode >= 0700 (448)
    event.data.exec.new_process.file.mode = 0755;
    // pred 13: target.process.file.suid == 0
    event.data.exec.new_process.file.suid = 0;
    // pred 14: target.process.file.sgid == 0
    event.data.exec.new_process.file.sgid = 0;
    // pred 15: target.process.file.nlink >= 1
    event.data.exec.new_process.file.nlink = 1;
    // pred 16: target.process.file.type == REGULAR_FILE (5)
    event.data.exec.new_process.file.type = REGULAR_FILE;

    // Process fields (predicates 17-22)
    // pred 17: process.pid > 100
    event.process.pid = 500;
    // pred 18: process.ppid > 1
    event.process.ppid = 50;
    // pred 19: process.ruid == 1000
    event.process.ruid = 1000;
    // pred 20: process.euid == 1000
    event.process.euid = 1000;
    // pred 21: process.file.path startswith "/usr/"
    strncpy(event.process.file.path.value, "/usr/bin/bash", PATH_MAX);
    event.process.file.path.length = strlen("/usr/bin/bash");
    // pred 22: process.file.type == REGULAR_FILE (5)
    event.process.file.type = REGULAR_FILE;

    // Parent process fields (predicates 23-27) - OR condition
    // (parent_pid AND parent_ruid) OR (parent_euid AND parent_file_path AND parent_file_type)
    // pred 23: parent_process.pid > 1
    event.parent_process.pid = 10;
    // pred 24: parent_process.ruid == 1000
    event.parent_process.ruid = 1000;
    // pred 25: parent_process.euid == 1000
    event.parent_process.euid = 1000;
    // pred 26: parent_process.file.path startswith "/usr/"
    strncpy(event.parent_process.file.path.value, "/usr/bin/init", PATH_MAX);
    event.parent_process.file.path.length = strlen("/usr/bin/init");
    // pred 27: parent_process.file.type == REGULAR_FILE (5)
    event.parent_process.file.type = REGULAR_FILE;

    // Exclusions - these must NOT match (NOT operators)
    // pred 28: process.euid == 0 - must be FALSE (we set 1000)
    // pred 29: target.process.file.path contains "dangerous" - must be FALSE

    return event;
}

// Event that should NOT match EXEC ALL FIELDS rule
// Fails only on pred 7: target.process.cmd doesn't contain "script"
inline event_t create_exec_all_fields_non_matching_event() {
    event_t event = create_exec_all_fields_matching_event();
    // Break pred 7: target.process.cmd doesn't contain "script"
    strncpy(event.data.exec.new_process.cmd.value, "/tmp/test_program.sh --arg1", CMD_MAX);
    event.data.exec.new_process.cmd.length = strlen("/tmp/test_program.sh --arg1");
    return event;
}

// ============================================================================
// IP MATCHING JSON - NETWORK (source_ip and destination_ip tests)
// Tests CIDR matching for IPv4 and IPv6 addresses
// ============================================================================
constexpr const char* IP_SOURCE_IPV4_MASK32_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "network.source_ip",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {
    "0": {
      "ip": "192.168.1.100",
      "cidr": 32,
      "ip_type": 2
    }
  },
  "rules": [
    {
      "id": 6001,
      "description": "Test source_ip IPv4 exact match. mask is 32",
      "action": "BLOCK_EVENT",
      "applied_events": ["NETWORK"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

constexpr const char* IP_SOURCE_IPV4_MASK24_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "network.source_ip",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {
    "0": {
      "ip": "192.168.1.0",
      "cidr": 24,
      "ip_type": 2
    }
  },
  "rules": [
    {
      "id": 6002,
      "description": "Test source_ip IPv4 subnet match. mask is 24",
      "action": "BLOCK_EVENT",
      "applied_events": ["NETWORK"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

constexpr const char* IP_SOURCE_IPV4_MASK0_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "network.source_ip",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {
    "0": {
      "ip": "0.0.0.0",
      "cidr": 0,
      "ip_type": 2
    }
  },
  "rules": [
    {
      "id": 6003,
      "description": "Test source_ip IPv4 match all. mask is 0",
      "action": "BLOCK_EVENT",
      "applied_events": ["NETWORK"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

constexpr const char* IP_SOURCE_IPV6_MASK128_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "network.source_ip",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {
    "0": {
      "ip": "2001:0db8:0000:0000:0000:0000:0000:0001",
      "cidr": 128,
      "ip_type": 10
    }
  },
  "rules": [
    {
      "id": 6004,
      "description": "Test source_ip IPv6 exact match mask is 128",
      "action": "BLOCK_EVENT",
      "applied_events": ["NETWORK"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

constexpr const char* IP_SOURCE_IPV6_MASK64_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "network.source_ip",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {
    "0": {
      "ip": "2001:0db8:0000:0000:0000:0000:0000:0000",
      "cidr": 64,
      "ip_type": 10
    }
  },
  "rules": [
    {
      "id": 6005,
      "description": "Test source_ip IPv6 subnet match mask is 64",
      "action": "BLOCK_EVENT",
      "applied_events": ["NETWORK"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

constexpr const char* IP_SOURCE_IPV6_MASK0_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "network.source_ip",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {
    "0": {
      "ip": "0000:0000:0000:0000:0000:0000:0000:0000",
      "cidr": 0,
      "ip_type": 10
    }
  },
  "rules": [
    {
      "id": 6006,
      "description": "Test source_ip IPv6 match all. mask is 0",
      "action": "BLOCK_EVENT",
      "applied_events": ["NETWORK"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

// Destination IP JSONs
constexpr const char* IP_DEST_IPV4_MASK32_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "network.destination_ip",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {
    "0": {
      "ip": "10.0.0.1",
      "cidr": 32,
      "ip_type": 2
    }
  },
  "rules": [
    {
      "id": 6101,
      "description": "Test destination_ip IPv4 exact match. mask is 32",
      "action": "BLOCK_EVENT",
      "applied_events": ["NETWORK"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

constexpr const char* IP_DEST_IPV4_MASK24_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "network.destination_ip",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {
    "0": {
      "ip": "10.0.0.0",
      "cidr": 24,
      "ip_type": 2
    }
  },
  "rules": [
    {
      "id": 6102,
      "description": "Test destination_ip IPv4 subnet match. mask is 24",
      "action": "BLOCK_EVENT",
      "applied_events": ["NETWORK"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

constexpr const char* IP_DEST_IPV4_MASK0_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "network.destination_ip",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {
    "0": {
      "ip": "0.0.0.0",
      "cidr": 0,
      "ip_type": 2
    }
  },
  "rules": [
    {
      "id": 6103,
      "description": "Test destination_ip IPv4 match all. mask is 0",
      "action": "BLOCK_EVENT",
      "applied_events": ["NETWORK"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

constexpr const char* IP_DEST_IPV6_MASK128_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "network.destination_ip",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {
    "0": {
      "ip": "fe80:0000:0000:0000:0000:0000:0000:0001",
      "cidr": 128,
      "ip_type": 10
    }
  },
  "rules": [
    {
      "id": 6104,
      "description": "Test destination_ip IPv6 exact match. mask is 128",
      "action": "BLOCK_EVENT",
      "applied_events": ["NETWORK"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

constexpr const char* IP_DEST_IPV6_MASK64_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "network.destination_ip",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {
    "0": {
      "ip": "fe80:0000:0000:0000:0000:0000:0000:0000",
      "cidr": 64,
      "ip_type": 10
    }
  },
  "rules": [
    {
      "id": 6105,
      "description": "Test destination_ip IPv6 subnet match. mask is 64",
      "action": "BLOCK_EVENT",
      "applied_events": ["NETWORK"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

constexpr const char* IP_DEST_IPV6_MASK0_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {
      "field": "network.destination_ip",
      "comparison_type": "equal",
      "string_idx": -1,
      "numerical_value": 0,
      "fieldref": "FIELD_TYPE_NONE"
    }
  },
  "id_to_ip": {
    "0": {
      "ip": "0000:0000:0000:0000:0000:0000:0000:0000",
      "cidr": 0,
      "ip_type": 10
    }
  },
  "rules": [
    {
      "id": 6106,
      "description": "Test destination_ip IPv6 match all. mask is 0",
      "action": "BLOCK_EVENT",
      "applied_events": ["NETWORK"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

// ============================================================================
// IP MATCHING TEST EVENTS - NETWORK
// ============================================================================

// Helper to convert IPv4 string to network byte order uint32
inline unsigned int ipv4_str_to_be(const char* ip_str) {
    unsigned int a, b, c, d;
    sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d);
    return (d << 24) | (c << 16) | (b << 8) | a;  // Network byte order (little-endian representation)
}

// Helper to set IPv6 address from hex segments
inline void set_ipv6_addr(unsigned int dest[4], unsigned int a, unsigned int b, unsigned int c, unsigned int d) {
    dest[0] = a;
    dest[1] = b;
    dest[2] = c;
    dest[3] = d;
}

// --- Source IP IPv4 Events ---

// Event matching source_ip 192.168.1.100/32
inline event_t create_network_source_ipv4_mask32_match() {
    event_t event = {};
    event.type = NETWORK;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.data.network.ip_type = AF_INET;
    event.data.network.direction = OUTGOING;
    event.data.network.source_port = 12345;
    event.data.network.destination_port = 80;
    event.data.network.addresses.ipv4.source_ip = ipv4_str_to_be("192.168.1.100");
    event.data.network.addresses.ipv4.destination_ip = ipv4_str_to_be("8.8.8.8");
    return event;
}

// Event NOT matching source_ip 192.168.1.100/32 (different IP)
inline event_t create_network_source_ipv4_mask32_no_match() {
    event_t event = create_network_source_ipv4_mask32_match();
    event.data.network.addresses.ipv4.source_ip = ipv4_str_to_be("192.168.1.101");
    return event;
}

// Event matching source_ip 192.168.1.0/24 (any 192.168.1.x)
inline event_t create_network_source_ipv4_mask24_match() {
    event_t event = {};
    event.type = NETWORK;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.data.network.ip_type = AF_INET;
    event.data.network.direction = OUTGOING;
    event.data.network.source_port = 12345;
    event.data.network.destination_port = 80;
    event.data.network.addresses.ipv4.source_ip = ipv4_str_to_be("192.168.1.50");
    event.data.network.addresses.ipv4.destination_ip = ipv4_str_to_be("8.8.8.8");
    return event;
}

// Event NOT matching source_ip 192.168.1.0/24 (192.168.2.x is outside)
inline event_t create_network_source_ipv4_mask24_no_match() {
    event_t event = create_network_source_ipv4_mask24_match();
    event.data.network.addresses.ipv4.source_ip = ipv4_str_to_be("192.168.2.50");
    return event;
}

// Event matching source_ip 0.0.0.0/0 (matches any IP)
inline event_t create_network_source_ipv4_mask0_match() {
    event_t event = {};
    event.type = NETWORK;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.data.network.ip_type = AF_INET;
    event.data.network.direction = OUTGOING;
    event.data.network.source_port = 12345;
    event.data.network.destination_port = 80;
    event.data.network.addresses.ipv4.source_ip = ipv4_str_to_be("172.16.255.1");
    event.data.network.addresses.ipv4.destination_ip = ipv4_str_to_be("8.8.8.8");
    return event;
}

// --- Source IP IPv6 Events ---

// Event matching source_ip 2001:db8::1/128
inline event_t create_network_source_ipv6_mask128_match() {
    event_t event = {};
    event.type = NETWORK;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.data.network.ip_type = AF_INET6;
    event.data.network.direction = OUTGOING;
    event.data.network.source_port = 12345;
    event.data.network.destination_port = 80;
    // 2001:0db8:0000:0000:0000:0000:0000:0001 in network byte order
    set_ipv6_addr(event.data.network.addresses.ipv6.source_ip, 
                  0xb80d0120, 0x00000000, 0x00000000, 0x01000000);
    set_ipv6_addr(event.data.network.addresses.ipv6.destination_ip,
                  0x00000000, 0x00000000, 0x00000000, 0x00000000);
    return event;
}

// Event NOT matching source_ip 2001:db8::1/128
inline event_t create_network_source_ipv6_mask128_no_match() {
    event_t event = create_network_source_ipv6_mask128_match();
    // 2001:0db8:0000:0000:0000:0000:0000:0002 - different last byte
    set_ipv6_addr(event.data.network.addresses.ipv6.source_ip,
                  0xb80d0120, 0x00000000, 0x00000000, 0x02000000);
    return event;
}

// Event matching source_ip 2001:db8::/64 (same prefix)
inline event_t create_network_source_ipv6_mask64_match() {
    event_t event = {};
    event.type = NETWORK;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.data.network.ip_type = AF_INET6;
    event.data.network.direction = OUTGOING;
    event.data.network.source_port = 12345;
    event.data.network.destination_port = 80;
    // 2001:0db8:0000:0000:1234:5678:9abc:def0 - same /64 prefix
    set_ipv6_addr(event.data.network.addresses.ipv6.source_ip,
                  0xb80d0120, 0x00000000, 0x78563412, 0xf0debc9a);
    set_ipv6_addr(event.data.network.addresses.ipv6.destination_ip,
                  0x00000000, 0x00000000, 0x00000000, 0x00000000);
    return event;
}

// Event NOT matching source_ip 2001:db8::/64 (different /64 prefix)
inline event_t create_network_source_ipv6_mask64_no_match() {
    event_t event = create_network_source_ipv6_mask64_match();
    // 2001:0db9:0000:0000:... - different prefix
    set_ipv6_addr(event.data.network.addresses.ipv6.source_ip,
                  0xb90d0120, 0x00000000, 0x78563412, 0xf0debc9a);
    return event;
}

// Event matching ::/0 (matches any IPv6)
inline event_t create_network_source_ipv6_mask0_match() {
    event_t event = {};
    event.type = NETWORK;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.data.network.ip_type = AF_INET6;
    event.data.network.direction = OUTGOING;
    event.data.network.source_port = 12345;
    event.data.network.destination_port = 80;
    // Any random IPv6 address
    set_ipv6_addr(event.data.network.addresses.ipv6.source_ip,
                  0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0);
    set_ipv6_addr(event.data.network.addresses.ipv6.destination_ip,
                  0x00000000, 0x00000000, 0x00000000, 0x00000000);
    return event;
}

// --- Destination IP IPv4 Events ---

// Event matching destination_ip 10.0.0.1/32
inline event_t create_network_dest_ipv4_mask32_match() {
    event_t event = {};
    event.type = NETWORK;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.data.network.ip_type = AF_INET;
    event.data.network.direction = OUTGOING;
    event.data.network.source_port = 12345;
    event.data.network.destination_port = 80;
    event.data.network.addresses.ipv4.source_ip = ipv4_str_to_be("192.168.1.1");
    event.data.network.addresses.ipv4.destination_ip = ipv4_str_to_be("10.0.0.1");
    return event;
}

// Event NOT matching destination_ip 10.0.0.1/32
inline event_t create_network_dest_ipv4_mask32_no_match() {
    event_t event = create_network_dest_ipv4_mask32_match();
    event.data.network.addresses.ipv4.destination_ip = ipv4_str_to_be("10.0.0.2");
    return event;
}

// Event matching destination_ip 10.0.0.0/24
inline event_t create_network_dest_ipv4_mask24_match() {
    event_t event = {};
    event.type = NETWORK;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.data.network.ip_type = AF_INET;
    event.data.network.direction = OUTGOING;
    event.data.network.source_port = 12345;
    event.data.network.destination_port = 80;
    event.data.network.addresses.ipv4.source_ip = ipv4_str_to_be("192.168.1.1");
    event.data.network.addresses.ipv4.destination_ip = ipv4_str_to_be("10.0.0.200");
    return event;
}

// Event NOT matching destination_ip 10.0.0.0/24
inline event_t create_network_dest_ipv4_mask24_no_match() {
    event_t event = create_network_dest_ipv4_mask24_match();
    event.data.network.addresses.ipv4.destination_ip = ipv4_str_to_be("10.0.1.200");
    return event;
}

// Event matching destination_ip 0.0.0.0/0 (any)
inline event_t create_network_dest_ipv4_mask0_match() {
    event_t event = {};
    event.type = NETWORK;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.data.network.ip_type = AF_INET;
    event.data.network.direction = OUTGOING;
    event.data.network.source_port = 12345;
    event.data.network.destination_port = 80;
    event.data.network.addresses.ipv4.source_ip = ipv4_str_to_be("192.168.1.1");
    event.data.network.addresses.ipv4.destination_ip = ipv4_str_to_be("255.255.255.255");
    return event;
}

// --- Destination IP IPv6 Events ---

// Event matching destination_ip fe80::1/128
inline event_t create_network_dest_ipv6_mask128_match() {
    event_t event = {};
    event.type = NETWORK;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.data.network.ip_type = AF_INET6;
    event.data.network.direction = OUTGOING;
    event.data.network.source_port = 12345;
    event.data.network.destination_port = 80;
    set_ipv6_addr(event.data.network.addresses.ipv6.source_ip,
                  0x00000000, 0x00000000, 0x00000000, 0x00000000);
    // fe80:0000:0000:0000:0000:0000:0000:0001
    set_ipv6_addr(event.data.network.addresses.ipv6.destination_ip,
                  0x000080fe, 0x00000000, 0x00000000, 0x01000000);
    return event;
}

// Event NOT matching destination_ip fe80::1/128
inline event_t create_network_dest_ipv6_mask128_no_match() {
    event_t event = create_network_dest_ipv6_mask128_match();
    // fe80:0000:0000:0000:0000:0000:0000:0002
    set_ipv6_addr(event.data.network.addresses.ipv6.destination_ip,
                  0x000080fe, 0x00000000, 0x00000000, 0x02000000);
    return event;
}

// Event matching destination_ip fe80::/64
inline event_t create_network_dest_ipv6_mask64_match() {
    event_t event = {};
    event.type = NETWORK;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.data.network.ip_type = AF_INET6;
    event.data.network.direction = OUTGOING;
    event.data.network.source_port = 12345;
    event.data.network.destination_port = 80;
    set_ipv6_addr(event.data.network.addresses.ipv6.source_ip,
                  0x00000000, 0x00000000, 0x00000000, 0x00000000);
    // fe80:0000:0000:0000:1234:5678:9abc:def0
    set_ipv6_addr(event.data.network.addresses.ipv6.destination_ip,
                  0x000080fe, 0x00000000, 0x78563412, 0xf0debc9a);
    return event;
}

// Event NOT matching destination_ip fe80::/64
inline event_t create_network_dest_ipv6_mask64_no_match() {
    event_t event = create_network_dest_ipv6_mask64_match();
    // fe81:0000:0000:0000:... - different prefix
    set_ipv6_addr(event.data.network.addresses.ipv6.destination_ip,
                  0x000081fe, 0x00000000, 0x78563412, 0xf0debc9a);
    return event;
}

// Event matching ::/0 destination (any IPv6)
inline event_t create_network_dest_ipv6_mask0_match() {
    event_t event = {};
    event.type = NETWORK;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.data.network.ip_type = AF_INET6;
    event.data.network.direction = OUTGOING;
    event.data.network.source_port = 12345;
    event.data.network.destination_port = 80;
    set_ipv6_addr(event.data.network.addresses.ipv6.source_ip,
                  0x00000000, 0x00000000, 0x00000000, 0x00000000);
    // Any random IPv6
    set_ipv6_addr(event.data.network.addresses.ipv6.destination_ip,
                  0xaabbccdd, 0xeeff0011, 0x22334455, 0x66778899);
    return event;
}

// ============================================================================
// FIELDREF NUMERIC TESTS
// ============================================================================

constexpr const char* FIELDREF_NUMERIC_JSON = R"({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {"field": "process.euid", "comparison_type": "equal", "string_idx": -1, "numerical_value": -1, "fieldref": "PARENT_PROCESS_EUID"},
    "1": {"field": "process.pid", "comparison_type": "above", "string_idx": -1, "numerical_value": -1, "fieldref": "PARENT_PROCESS_PID"},
    "2": {"field": "process.pid", "comparison_type": "equal_above", "string_idx": -1, "numerical_value": -1, "fieldref": "PARENT_PROCESS_PID"},
    "3": {"field": "process.rgid", "comparison_type": "below", "string_idx": -1, "numerical_value": -1, "fieldref": "PARENT_PROCESS_RGID"},
    "4": {"field": "process.ruid", "comparison_type": "equal_below", "string_idx": -1, "numerical_value": -1, "fieldref": "PARENT_PROCESS_RUID"},
    "5": {"field": "process.ruid", "comparison_type": "above", "string_idx": -1, "numerical_value": -1, "fieldref": "PARENT_PROCESS_RUID"},
    "6": {"field": "process.pid", "comparison_type": "equal", "string_idx": -1, "numerical_value": -1, "fieldref": "PARENT_PROCESS_PID"}
  },
  "id_to_ip": {},
  "rules": [
    {
      "id": 7001,
      "description": "fieldref equal - process.euid == parent_process.euid",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHMOD"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    },
    {
      "id": 7004,
      "description": "fieldref gt - process.pid > parent_process.pid",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHMOD"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 1}
      ]
    },
    {
      "id": 7002,
      "description": "fieldref gte - process.pid >= parent_process.pid",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHMOD"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 2}
      ]
    },
    {
      "id": 7005,
      "description": "fieldref lt - process.rgid < parent_process.rgid",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHMOD"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 3}
      ]
    },
    {
      "id": 7003,
      "description": "fieldref lte - process.ruid <= parent_process.ruid",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHMOD"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 4}
      ]
    },
    {
      "id": 7007,
      "description": "multiple fieldrefs in one rule",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHMOD"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 2},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 5},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_AND"}
      ]
    },
    {
      "id": 7006,
      "description": "fieldref neq - process.pid != parent_process.pid",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHMOD"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 6},
        {"operator_type": "OPERATOR_NOT"}
      ]
    }
  ]
})";

// --- Fieldref Numeric Event Creators ---

inline event_t create_fieldref_equal_match() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.euid = 500;
    event.parent_process.euid = 500;
    return event;
}

inline event_t create_fieldref_equal_no_match() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.euid = 500;
    event.parent_process.euid = 999;
    return event;
}

inline event_t create_fieldref_gte_match_greater() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.pid = 200;
    event.parent_process.pid = 100;
    return event;
}

inline event_t create_fieldref_gte_match_equal() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.pid = 100;
    event.parent_process.pid = 100;
    return event;
}

inline event_t create_fieldref_gte_no_match() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.pid = 50;
    event.parent_process.pid = 100;
    return event;
}

inline event_t create_fieldref_gt_match() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.pid = 200;
    event.parent_process.pid = 100;
    return event;
}

inline event_t create_fieldref_gt_no_match_equal() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.pid = 100;
    event.parent_process.pid = 100;
    return event;
}

inline event_t create_fieldref_gt_no_match_less() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.pid = 50;
    event.parent_process.pid = 100;
    return event;
}

inline event_t create_fieldref_lte_match_less() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.ruid = 50;
    event.parent_process.ruid = 100;
    return event;
}

inline event_t create_fieldref_lte_match_equal() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.ruid = 100;
    event.parent_process.ruid = 100;
    return event;
}

inline event_t create_fieldref_lte_no_match() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.ruid = 200;
    event.parent_process.ruid = 100;
    return event;
}

inline event_t create_fieldref_lt_match() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.rgid = 50;
    event.parent_process.rgid = 100;
    return event;
}

inline event_t create_fieldref_lt_no_match_equal() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.rgid = 100;
    event.parent_process.rgid = 100;
    return event;
}

inline event_t create_fieldref_lt_no_match_greater() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.rgid = 200;
    event.parent_process.rgid = 100;
    return event;
}

inline event_t create_fieldref_neq_match() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.pid = 200;
    event.parent_process.pid = 100;
    return event;
}

inline event_t create_fieldref_neq_no_match() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.pid = 100;
    event.parent_process.pid = 100;
    return event;
}

// All three conditions: euid==parent_euid AND pid>=parent_pid AND ruid>parent_ruid
inline event_t create_fieldref_multi_match() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.euid = 500;
    event.parent_process.euid = 500;
    event.process.pid = 200;
    event.parent_process.pid = 100;
    event.process.ruid = 300;
    event.parent_process.ruid = 100;
    return event;
}

// euid matches, pid matches (gte), but ruid fails (not >)
inline event_t create_fieldref_multi_no_match_one_fails() {
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    event.process.euid = 500;
    event.parent_process.euid = 500;
    event.process.pid = 200;
    event.parent_process.pid = 100;
    event.process.ruid = 50;
    event.parent_process.ruid = 100;
    return event;
}

// ============================================================================
// FIELDREF STRING TESTS
// ============================================================================

constexpr const char* FIELDREF_STRING_JSON = R"JSON({
  "id_to_string": {},
  "id_to_predicate": {
    "0": {"field": "process.file.filename", "comparison_type": "exactmatch", "string_idx": -1, "numerical_value": -1, "fieldref": "PROCESS_CMD"},
    "1": {"field": "process.file.filename", "comparison_type": "startswith", "string_idx": -1, "numerical_value": -1, "fieldref": "PROCESS_CMD"},
    "2": {"field": "process.file.filename", "comparison_type": "endswith", "string_idx": -1, "numerical_value": -1, "fieldref": "PROCESS_CMD"},
    "3": {"field": "process.cmd", "comparison_type": "exactmatch", "string_idx": -1, "numerical_value": -1, "fieldref": "PROCESS_FILE_FILENAME"},
    "4": {"field": "process.cmd", "comparison_type": "startswith", "string_idx": -1, "numerical_value": -1, "fieldref": "PROCESS_FILE_FILENAME"},
    "5": {"field": "process.cmd", "comparison_type": "endswith", "string_idx": -1, "numerical_value": -1, "fieldref": "PROCESS_FILE_FILENAME"},
    "6": {"field": "parent_process.file.filename", "comparison_type": "exactmatch", "string_idx": -1, "numerical_value": -1, "fieldref": "PARENT_PROCESS_CMD"},
    "7": {"field": "parent_process.cmd", "comparison_type": "exactmatch", "string_idx": -1, "numerical_value": -1, "fieldref": "PROCESS_CMD"},
    "8": {"field": "parent_process.cmd", "comparison_type": "startswith", "string_idx": -1, "numerical_value": -1, "fieldref": "PROCESS_CMD"},
    "9": {"field": "parent_process.cmd", "comparison_type": "endswith", "string_idx": -1, "numerical_value": -1, "fieldref": "PROCESS_CMD"}
  },
  "id_to_ip": {},
  "rules": [
    {
      "id": 8001,
      "description": "Fieldref string: process.file.filename exactmatch process.cmd (haystack=filename, needle=cmd)",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    },
    {
      "id": 8002,
      "description": "Fieldref string: process.file.filename startswith process.cmd (haystack=filename, needle=cmd)",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 1}
      ]
    },
    {
      "id": 8003,
      "description": "Fieldref string: process.file.filename endswith process.cmd (haystack=filename, needle=cmd)",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 2}
      ]
    },
    {
      "id": 8004,
      "description": "Fieldref string: process.cmd exactmatch process.file.filename (haystack=cmd, needle=filename)",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 3}
      ]
    },
    {
      "id": 8005,
      "description": "Fieldref string: process.cmd startswith process.file.filename (haystack=cmd, needle=filename)",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 4}
      ]
    },
    {
      "id": 8006,
      "description": "Fieldref string: process.cmd endswith process.file.filename (haystack=cmd, needle=filename)",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 5}
      ]
    },
    {
      "id": 8007,
      "description": "Fieldref string: process.file.filename neq process.cmd (NOT exactmatch)",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
        {"operator_type": "OPERATOR_NOT"}
      ]
    },
    {
      "id": 8008,
      "description": "Fieldref string: multiple fieldrefs - filename==cmd AND parent_filename==parent_cmd",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 6},
        {"operator_type": "OPERATOR_AND"}
      ]
    },
    {
      "id": 8009,
      "description": "Fieldref string: parent_process.cmd exactmatch process.cmd (for max-length and empty-needle tests)",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 7}
      ]
    },
    {
      "id": 8010,
      "description": "Fieldref string: parent_process.cmd startswith process.cmd (for max-length and empty-needle tests)",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 8}
      ]
    },
    {
      "id": 8011,
      "description": "Fieldref string: parent_process.cmd endswith process.cmd (for max-length and empty-needle tests)",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 9}
      ]
    }
  ]
})JSON";

// ============================================================================
// FIELDREF STRING EVENT CREATORS
// ============================================================================

// --- Helpers ---

inline void set_filename(event_t& event, const char* str)
{
    auto len = static_cast<short>(strlen(str));
    strncpy(event.process.file.filename.value, str, FILENAME_MAX_LENGTH - 1);
    event.process.file.filename.length = len;
}

inline void set_cmd(event_t& event, const char* str)
{
    auto len = static_cast<short>(strlen(str));
    strncpy(event.process.cmd.value, str, CMD_MAX - 1);
    event.process.cmd.length = len;
}

inline void set_parent_filename(event_t& event, const char* str)
{
    auto len = static_cast<short>(strlen(str));
    strncpy(event.parent_process.file.filename.value, str, FILENAME_MAX_LENGTH - 1);
    event.parent_process.file.filename.length = len;
}

inline void set_parent_cmd(event_t& event, const char* str)
{
    auto len = static_cast<short>(strlen(str));
    strncpy(event.parent_process.cmd.value, str, CMD_MAX - 1);
    event.parent_process.cmd.length = len;
}

inline event_t make_exec_event()
{
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;
    return event;
}

// --- Rule 8001: filename|fieldref: cmd (exactmatch, haystack=filename, needle=cmd) ---

// filename == cmd → MATCH
inline event_t create_fieldref_str_filename_cmd_exactmatch_match()
{
    auto event = make_exec_event();
    set_filename(event, "bash");
    set_cmd(event, "bash");
    return event;
}

// filename != cmd (different lengths) → NO MATCH
inline event_t create_fieldref_str_filename_cmd_exactmatch_no_match()
{
    auto event = make_exec_event();
    set_filename(event, "bash");
    set_cmd(event, "sh");
    return event;
}

// --- Rule 8002: filename|startswith|fieldref: cmd (haystack=filename, needle=cmd) ---

// filename starts with cmd → MATCH ("bash_script" starts with "bash")
inline event_t create_fieldref_str_filename_cmd_startswith_match()
{
    auto event = make_exec_event();
    set_filename(event, "bash_script");
    set_cmd(event, "bash");
    return event;
}

// filename does not start with cmd → NO MATCH ("run_bash" does not start with "bash")
inline event_t create_fieldref_str_filename_cmd_startswith_no_match()
{
    auto event = make_exec_event();
    set_filename(event, "run_bash");
    set_cmd(event, "bash");
    return event;
}

// --- Rule 8003: filename|endswith|fieldref: cmd (haystack=filename, needle=cmd) ---

// filename ends with cmd → MATCH ("run_bash" ends with "bash")
inline event_t create_fieldref_str_filename_cmd_endswith_match()
{
    auto event = make_exec_event();
    set_filename(event, "run_bash");
    set_cmd(event, "bash");
    return event;
}

// filename does not end with cmd → NO MATCH ("bash_run" does not end with "bash")
inline event_t create_fieldref_str_filename_cmd_endswith_no_match()
{
    auto event = make_exec_event();
    set_filename(event, "bash_run");
    set_cmd(event, "bash");
    return event;
}

// --- Rule 8004: cmd|fieldref: filename (exactmatch, haystack=cmd, needle=filename) ---

// cmd == filename → MATCH
inline event_t create_fieldref_str_cmd_filename_exactmatch_match()
{
    auto event = make_exec_event();
    set_cmd(event, "python3");
    set_filename(event, "python3");
    return event;
}

// cmd != filename (different content) → NO MATCH
inline event_t create_fieldref_str_cmd_filename_exactmatch_no_match()
{
    auto event = make_exec_event();
    set_cmd(event, "python3");
    set_filename(event, "python2");
    return event;
}

// --- Rule 8005: cmd|startswith|fieldref: filename (haystack=cmd, needle=filename) ---

// cmd starts with filename → MATCH ("bash_runner" starts with "bash")
inline event_t create_fieldref_str_cmd_filename_startswith_match()
{
    auto event = make_exec_event();
    set_cmd(event, "bash_runner");
    set_filename(event, "bash");
    return event;
}

// cmd does not start with filename → NO MATCH ("run_bash" does not start with "bash")
inline event_t create_fieldref_str_cmd_filename_startswith_no_match()
{
    auto event = make_exec_event();
    set_cmd(event, "run_bash");
    set_filename(event, "bash");
    return event;
}

// --- Rule 8006: cmd|endswith|fieldref: filename (haystack=cmd, needle=filename) ---

// cmd ends with filename → MATCH ("run_bash" ends with "bash")
inline event_t create_fieldref_str_cmd_filename_endswith_match()
{
    auto event = make_exec_event();
    set_cmd(event, "run_bash");
    set_filename(event, "bash");
    return event;
}

// cmd does not end with filename → NO MATCH ("bash_run" does not end with "bash")
inline event_t create_fieldref_str_cmd_filename_endswith_no_match()
{
    auto event = make_exec_event();
    set_cmd(event, "bash_run");
    set_filename(event, "bash");
    return event;
}

// --- Rule 8007: filename|neq|fieldref: cmd (NOT exactmatch) ---

// filename != cmd → NOT(exactmatch) = TRUE → MATCH
inline event_t create_fieldref_str_filename_cmd_neq_match()
{
    auto event = make_exec_event();
    set_filename(event, "bash");
    set_cmd(event, "sh");
    return event;
}

// filename == cmd → NOT(exactmatch) = FALSE → NO MATCH
inline event_t create_fieldref_str_filename_cmd_neq_no_match()
{
    auto event = make_exec_event();
    set_filename(event, "bash");
    set_cmd(event, "bash");
    return event;
}

// --- Rule 8008: filename|fieldref: cmd AND parent_filename|fieldref: parent_cmd ---

// Both predicates match → MATCH
inline event_t create_fieldref_str_multi_fieldref_match()
{
    auto event = make_exec_event();
    set_filename(event, "bash");
    set_cmd(event, "bash");
    set_parent_filename(event, "sh");
    set_parent_cmd(event, "sh");
    return event;
}

// First predicate fails (filename != cmd) → NO MATCH
inline event_t create_fieldref_str_multi_fieldref_no_match_first_fails()
{
    auto event = make_exec_event();
    set_filename(event, "bash");
    set_cmd(event, "sh");
    set_parent_filename(event, "sh");
    set_parent_cmd(event, "sh");
    return event;
}

// Second predicate fails (parent_filename != parent_cmd) → NO MATCH
inline event_t create_fieldref_str_multi_fieldref_no_match_second_fails()
{
    auto event = make_exec_event();
    set_filename(event, "bash");
    set_cmd(event, "bash");
    set_parent_filename(event, "sh");
    set_parent_cmd(event, "bash");
    return event;
}

// --- Needle longer than haystack (rules 8001, 8002, 8003) ---
// filename (5 chars) is shorter than cmd (28 chars) → all comparisons must be FALSE
inline event_t create_fieldref_str_needle_longer_than_haystack()
{
    auto event = make_exec_event();
    set_filename(event, "short");
    set_cmd(event, "this_is_a_much_longer_string");
    return event;
}

// --- Empty needle: process.cmd is empty (rules 8001-8003, 8009-8011) ---
// All string comparisons must return FALSE when the needle length is 0
inline event_t create_fieldref_str_empty_needle()
{
    auto event = make_exec_event();
    set_filename(event, "bash");
    event.process.cmd.length = 0;
    event.process.cmd.value[0] = '\0';
    set_parent_cmd(event, "hello");
    return event;
}

// --- Rule 8009: parent_cmd|fieldref: cmd (exactmatch) - max length tests ---

// Both parent_cmd and cmd are 255 chars of 'a' → MATCH
inline event_t create_fieldref_str_max_len_exactmatch_match()
{
    auto event = make_exec_event();
    const std::string s(255, 'a');
    memcpy(event.parent_process.cmd.value, s.c_str(), 255);
    event.parent_process.cmd.length = 255;
    memcpy(event.process.cmd.value, s.c_str(), 255);
    event.process.cmd.length = 255;
    return event;
}

// parent_cmd starts with 'b' (first char differs) → NO MATCH
inline event_t create_fieldref_str_max_len_exactmatch_no_match()
{
    auto event = make_exec_event();
    const std::string needle(255, 'a');
    std::string haystack = std::string(1, 'b') + std::string(254, 'a');
    memcpy(event.parent_process.cmd.value, haystack.c_str(), 255);
    event.parent_process.cmd.length = 255;
    memcpy(event.process.cmd.value, needle.c_str(), 255);
    event.process.cmd.length = 255;
    return event;
}

// --- Rule 8010: parent_cmd|startswith|fieldref: cmd - max length tests ---

// parent_cmd = 255 chars of 'a', cmd = 128 chars of 'a' → parent starts with cmd → MATCH
inline event_t create_fieldref_str_max_len_startswith_match()
{
    auto event = make_exec_event();
    const std::string haystack(255, 'a');
    const std::string needle(128, 'a');
    memcpy(event.parent_process.cmd.value, haystack.c_str(), 255);
    event.parent_process.cmd.length = 255;
    memcpy(event.process.cmd.value, needle.c_str(), 128);
    event.process.cmd.length = 128;
    return event;
}

// parent_cmd starts with 'b', cmd is all 'a' → first char mismatch → NO MATCH
inline event_t create_fieldref_str_max_len_startswith_no_match()
{
    auto event = make_exec_event();
    const std::string haystack = std::string(1, 'b') + std::string(254, 'a');
    const std::string needle(128, 'a');
    memcpy(event.parent_process.cmd.value, haystack.c_str(), 255);
    event.parent_process.cmd.length = 255;
    memcpy(event.process.cmd.value, needle.c_str(), 128);
    event.process.cmd.length = 128;
    return event;
}

// --- Rule 8011: parent_cmd|endswith|fieldref: cmd - max length tests ---

// parent_cmd = 255 chars of 'a', cmd = 128 chars of 'a' → parent ends with cmd → MATCH
inline event_t create_fieldref_str_max_len_endswith_match()
{
    auto event = make_exec_event();
    const std::string haystack(255, 'a');
    const std::string needle(128, 'a');
    memcpy(event.parent_process.cmd.value, haystack.c_str(), 255);
    event.parent_process.cmd.length = 255;
    memcpy(event.process.cmd.value, needle.c_str(), 128);
    event.process.cmd.length = 128;
    return event;
}

// parent_cmd ends with 'b' (last char differs), cmd is all 'a' → NO MATCH
inline event_t create_fieldref_str_max_len_endswith_no_match()
{
    auto event = make_exec_event();
    const std::string haystack = std::string(254, 'a') + std::string(1, 'b');
    const std::string needle(128, 'a');
    memcpy(event.parent_process.cmd.value, haystack.c_str(), 255);
    event.parent_process.cmd.length = 255;
    memcpy(event.process.cmd.value, needle.c_str(), 128);
    event.process.cmd.length = 128;
    return event;
}

// --- Rule 8010/8011 with needle longer than haystack ---
// parent_cmd = 10 chars, cmd = 20 chars → needle longer → all FALSE
inline event_t create_fieldref_str_parent_cmd_needle_longer()
{
    auto event = make_exec_event();
    const std::string haystack(10, 'a');
    const std::string needle(20, 'a');
    memcpy(event.parent_process.cmd.value, haystack.c_str(), 10);
    event.parent_process.cmd.length = 10;
    memcpy(event.process.cmd.value, needle.c_str(), 20);
    event.process.cmd.length = 20;
    return event;
}

// ============================================================================
// REGEX TESTS
// ============================================================================

// Test 1: EXEC rule with multiple regex predicates (different regex features)
constexpr const char* REGEX_MULTI_FEATURE_JSON = R"({
  "id_to_string": {
    "0": {"value": "python[23]?", "string_type": 2},
    "1": {"value": "/usr/bin/[a-z0-9]+", "string_type": 2},
    "2": {"value": "[a-z]+_task", "string_type": 2}
  },
  "id_to_predicate": {
    "0": {"field": "process.file.filename", "comparison_type": "regex", "string_idx": 0, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "1": {"field": "target.process.file.path", "comparison_type": "regex", "string_idx": 1, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "2": {"field": "process.cmd", "comparison_type": "regex", "string_idx": 2, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"}
  },
  "id_to_ip": {},
  "rules": [
    {
      "id": 6001,
      "description": "EXEC with multiple regex predicates",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 1},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 2},
        {"operator_type": "OPERATOR_AND"}
      ]
    }
  ]
})";

inline event_t create_regex_multi_feature_matching_event()
{
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;

    strncpy(event.process.file.filename.value, "python3", FILENAME_MAX_LENGTH);
    event.process.file.filename.length = strlen("python3");

    strncpy(event.data.exec.new_process.file.path.value, "/usr/bin/python3", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/usr/bin/python3");

    strncpy(event.process.cmd.value, "backup_task", CMD_MAX);
    event.process.cmd.length = strlen("backup_task");

    return event;
}

inline event_t create_regex_multi_feature_non_matching_event()
{
    event_t event = create_regex_multi_feature_matching_event();
    strncpy(event.process.file.filename.value, "perl", FILENAME_MAX_LENGTH);
    event.process.file.filename.length = strlen("perl");
    return event;
}

// Test 2: Rule with 3 different fields, each using a different string type
constexpr const char* REGEX_MIXED_STRING_TYPES_JSON = R"({
  "id_to_string": {
    "0": {"value": "/usr/bin/", "string_type": 0},
    "1": {"value": "util", "string_type": 1},
    "2": {"value": "/tmp/[a-z]+", "string_type": 2}
  },
  "id_to_predicate": {
    "0": {"field": "process.file.path", "comparison_type": "startswith", "string_idx": 0, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "1": {"field": "process.cmd", "comparison_type": "contains", "string_idx": 1, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "2": {"field": "target.process.file.path", "comparison_type": "regex", "string_idx": 2, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"}
  },
  "id_to_ip": {},
  "rules": [
    {
      "id": 6002,
      "description": "Mixed string types: startswith, contains, regex on different fields",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 1},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 2},
        {"operator_type": "OPERATOR_AND"}
      ]
    }
  ]
})";

inline event_t create_mixed_types_matching_event()
{
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;

    strncpy(event.process.file.path.value, "/usr/bin/python", PATH_MAX);
    event.process.file.path.length = strlen("/usr/bin/python");

    strncpy(event.process.cmd.value, "testutil", CMD_MAX);
    event.process.cmd.length = strlen("testutil");

    strncpy(event.data.exec.new_process.file.path.value, "/tmp/backup", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/tmp/backup");

    return event;
}

inline event_t create_mixed_types_non_matching_event()
{
    event_t event = create_mixed_types_matching_event();
    strncpy(event.data.exec.new_process.file.path.value, "/home/backup", PATH_MAX);
    event.data.exec.new_process.file.path.length = strlen("/home/backup");
    return event;
}

// Test 3: Same field (process.cmd) with 3 different string types
constexpr const char* REGEX_SAME_FIELD_DIFFERENT_TYPES_JSON = R"({
  "id_to_string": {
    "0": {"value": "[a-z]+_script", "string_type": 2},
    "1": {"value": "script", "string_type": 1},
    "2": {"value": "test", "string_type": 0}
  },
  "id_to_predicate": {
    "0": {"field": "process.cmd", "comparison_type": "regex", "string_idx": 0, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "1": {"field": "process.cmd", "comparison_type": "contains", "string_idx": 1, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "2": {"field": "process.cmd", "comparison_type": "startswith", "string_idx": 2, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"}
  },
  "id_to_ip": {},
  "rules": [
    {
      "id": 6003,
      "description": "Same field with regex, contains, startswith",
      "action": "BLOCK_EVENT",
      "applied_events": ["EXEC"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 1},
        {"operator_type": "OPERATOR_AND"},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 2},
        {"operator_type": "OPERATOR_AND"}
      ]
    }
  ]
})";

inline event_t create_same_field_diff_types_matching_event()
{
    event_t event = {};
    event.type = EXEC;
    event.time = 1000;
    event.action = ALLOW_EVENT;

    strncpy(event.process.cmd.value, "test_script", CMD_MAX);
    event.process.cmd.length = strlen("test_script");

    return event;
}

inline event_t create_same_field_diff_types_non_matching_event()
{
    event_t event = create_same_field_diff_types_matching_event();
    strncpy(event.process.cmd.value, "run_script", CMD_MAX);
    event.process.cmd.length = strlen("run_script");
    return event;
}

// Test 4: Regex at state limit (30-char literal = 32 DFA states)
constexpr const char* REGEX_STATE_LIMIT_JSON = R"({
  "id_to_string": {
    "0": {"value": "abcdefghijklmnopqrstuvwxyz1234", "string_type": 2}
  },
  "id_to_predicate": {
    "0": {"field": "target.file.path", "comparison_type": "regex", "string_idx": 0, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"}
  },
  "id_to_ip": {},
  "rules": [
    {
      "id": 6004,
      "description": "Regex at max state limit",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHMOD"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0}
      ]
    }
  ]
})";

inline event_t create_state_limit_matching_event()
{
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;

    strncpy(event.data.chmod.file.path.value, "abcdefghijklmnopqrstuvwxyz1234", PATH_MAX);
    event.data.chmod.file.path.length = 30;

    return event;
}

inline event_t create_state_limit_non_matching_event()
{
    event_t event = create_state_limit_matching_event();
    strncpy(event.data.chmod.file.path.value, "abcdefghijklmnopqrstuvwxyz123", PATH_MAX);
    event.data.chmod.file.path.length = 29;
    return event;
}

// Test 5: CHMOD rule with regex + numeric predicates (OR logic)
constexpr const char* REGEX_WITH_OR_JSON = R"({
  "id_to_string": {
    "0": {"value": "/etc/[a-z]+\\.conf", "string_type": 2},
    "1": {"value": "/var/[a-z]+\\.cfg", "string_type": 2}
  },
  "id_to_predicate": {
    "0": {"field": "target.file.path", "comparison_type": "regex", "string_idx": 0, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"},
    "1": {"field": "target.file.path", "comparison_type": "regex", "string_idx": 1, "numerical_value": -1, "fieldref": "FIELD_TYPE_NONE"}
  },
  "id_to_ip": {},
  "rules": [
    {
      "id": 6005,
      "description": "Two regex patterns with OR",
      "action": "BLOCK_EVENT",
      "applied_events": ["CHMOD"],
      "tokens": [
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 0},
        {"operator_type": "OPERATOR_PREDICATE", "predicate_idx": 1},
        {"operator_type": "OPERATOR_OR"}
      ]
    }
  ]
})";

inline event_t create_regex_or_matching_event_first()
{
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;

    strncpy(event.data.chmod.file.path.value, "/etc/nginx.conf", PATH_MAX);
    event.data.chmod.file.path.length = strlen("/etc/nginx.conf");

    return event;
}

inline event_t create_regex_or_matching_event_second()
{
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;

    strncpy(event.data.chmod.file.path.value, "/var/app.cfg", PATH_MAX);
    event.data.chmod.file.path.length = strlen("/var/app.cfg");

    return event;
}

inline event_t create_regex_or_non_matching_event()
{
    event_t event = {};
    event.type = CHMOD;
    event.time = 1000;
    event.action = ALLOW_EVENT;

    strncpy(event.data.chmod.file.path.value, "/home/test.txt", PATH_MAX);
    event.data.chmod.file.path.length = strlen("/home/test.txt");

    return event;
}

} // namespace test_data

