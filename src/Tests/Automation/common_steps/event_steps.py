from pytest_bdd import given, when, then, parsers
import jmespath
from globals.system_related_globals import system_globals
from Utils.logger_utils import logger
import json
import os
import re
import time
import sys
from globals.global_strings import global_strings

def process_dynamic_placeholders(data, scenario_context=None):
    processed_data = {}
    
    def replace_placeholder(text):
        if not isinstance(text, str):
            return text

        placeholder_pattern = r'<([^>]+)>'
        matches = re.findall(placeholder_pattern, text)
        
        result = text
        for match in matches:
            placeholder = f'<{match}>'
            
            if match == 'automation_pid':
                replacement = str(os.getpid())
                result = result.replace(placeholder, replacement)
                logger.log_info(f"Replaced placeholder '{placeholder}' with '{replacement}'")
            if match == "automation_binary_path":
                replacement = os.path.realpath(sys.executable)
                result = result.replace(placeholder, replacement)
                logger.log_info(f"Replaced placeholder '{placeholder}' with '{replacement}'")
            if match == "USER_NAME":
                replacement = system_globals.USER_NAME
                result = result.replace(placeholder, replacement)
                logger.log_info(f"Replaced placeholder '{placeholder}' with '{replacement}'")
            if match == "resource_pid":
                replacement = str(scenario_context[global_strings.RESOURCE_PID])
                result = result.replace(placeholder, replacement)
                logger.log_info(f"Replaced placeholder '{placeholder}' with '{replacement}'")
            if match == "SERVER_IPv6_ADDR":
                replacement = system_globals.networking_globals.SERVER_IPv6_ADDR
                result = result.replace(placeholder, replacement)
                logger.log_info(f"Replaced placeholder '{placeholder}' with '{replacement}'")
            if match == "CLIENT_IPv6_ADDR":
                replacement = system_globals.networking_globals.CLIENT_IPv6_ADDR
                result = result.replace(placeholder, replacement)
                logger.log_info(f"Replaced placeholder '{placeholder}' with '{replacement}'")
            if match == "SERVER_IP_ADDR":
                replacement = system_globals.networking_globals.SERVER_IP_ADDR
                result = result.replace(placeholder, replacement)
                logger.log_info(f"Replaced placeholder '{placeholder}' with '{replacement}'")
            if match == "CLIENT_IP_ADDR":
                replacement = system_globals.networking_globals.CLIENT_IP_ADDR
                result = result.replace(placeholder, replacement)
                logger.log_info(f"Replaced placeholder '{placeholder}' with '{replacement}'")
            if match == "NETCAT_PATH":
                replacement = system_globals.networking_globals.NETCAT_PATH
                result = result.replace(placeholder, replacement)
                logger.log_info(f"Replaced placeholder '{placeholder}' with '{replacement}'")
            if match == "shell_pid":
                replacement = str(scenario_context[global_strings.SHELL_PID])
                result = result.replace(placeholder, replacement)
                logger.log_info(f"Replaced placeholder '{placeholder}' with '{replacement}'")
            else:
                logger.log_warning(f"Unknown placeholder: {placeholder}")
                
        return result
    
    for key, value in data.items():
        processed_key = replace_placeholder(key)
        processed_value = replace_placeholder(value)
        processed_data[processed_key] = processed_value
        
    return processed_data


@given(parsers.parse('I find the event in output in "{duration}" seconds:'))
@when(parsers.parse('I find the event in output in "{duration}" seconds:'))
@then(parsers.parse('I find the event in output in "{duration}" seconds:'))
def I_find_the_event_in_output(datatable, duration, scenario_context):
    success, expected = is_event_in_output(datatable, duration, scenario_context)
    assert success == True, f"Event not found in output: {expected}"


@given(parsers.parse('I dont find the event in output in "{duration}" seconds:'))
@when(parsers.parse('I dont find the event in output in "{duration}" seconds:'))
@then(parsers.parse('I dont find the event in output in "{duration}" seconds:'))
def I_dont_find_the_event_in_output(datatable, duration, scenario_context):
    success, expected = is_event_in_output(datatable, duration, scenario_context)
    assert success == False, f"Event found in output: {expected}"
    
                
def is_event_in_output(datatable, duration, scenario_context=None) -> (bool, dict):
    duration = int(duration)
    expected = {row[0].strip(): row[1].strip() for row in datatable}
    expected = process_dynamic_placeholders(expected, scenario_context)
    start_time = time.time()
    failed_to_parse_indexes = set()
    while time.time() - start_time < duration:
        with system_globals.OWLSM_OUTPUT_LOG.open('r', encoding='utf-8', errors='ignore') as f:
            index = 0
            for line in f:
                try:
                    line = line.strip()
                    index += 1
                    event = json.loads(line)
                    # for key, expected_value in expected.items():
                    #     actual_value = jmespath.search(key, event)
                    #     if str(actual_value) == str(expected_value):
                    #         logger.log_info(f"Found event {key} in output: {line}")
                    #         continue

                    if all(str(jmespath.search(key, event)).strip() == str(value).strip() for key, value in expected.items()):
                        logger.log_info(f"Found event in output: {line}")
                        return True, expected
                
                except Exception as e:
                    if index not in failed_to_parse_indexes:
                        logger.log_error(f"Error parsing line {index}: '{line}' \n{e}")
                        failed_to_parse_indexes.add(index)

    logger.log_error(f"Event not found in output: {expected}")
    return False, expected


@given(parsers.parse('I find the event in output exactly "{expected_count}" times in "{duration}" seconds:'))
@when(parsers.parse('I find the event in output exactly "{expected_count}" times in "{duration}" seconds:'))
@then(parsers.parse('I find the event in output exactly "{expected_count}" times in "{duration}" seconds:'))
def is_event_in_output_exactly_times(datatable, duration, scenario_context=None, expected_count=1) -> (bool, dict):
    duration = int(duration)
    expected = {row[0].strip(): row[1].strip() for row in datatable}
    expected = process_dynamic_placeholders(expected, scenario_context)
    start_time = time.time()
    failed_to_parse_indexes = set()
    found_count = 0
    while time.time() - start_time < duration:
        with system_globals.OWLSM_OUTPUT_LOG.open('r', encoding='utf-8', errors='ignore') as f:
            index = 0
            found_count = 0
            for line in f:
                try:
                    line = line.strip()
                    index += 1
                    event = json.loads(line)

                    if all(str(jmespath.search(key, event)).strip() == str(value).strip() for key, value in expected.items()):
                        logger.log_info(f"Found event in output: '{line}'. Expected: {expected_count} found: {found_count}")
                        found_count += 1
                
                except Exception as e:
                    if index not in failed_to_parse_indexes:
                        logger.log_error(f"Error parsing line {index}: '{line}' \n{e}")
                        failed_to_parse_indexes.add(index)


    if found_count == expected_count:
        return True, expected
    else:
        logger.log_error(f"Event not found in output: '{expected}'. Expected: {expected_count} found: {found_count}")
        return False, expected


@given(parsers.parse('I ensure that output file consists of at least "{count}" valid error message'))
@when(parsers.parse('I ensure that output file consists of at least "{count}" valid error message'))
@then(parsers.parse('I ensure that output file consists of at least "{count}" valid error message'))
def ensure_output_has_valid_error_messages(count):
    need = int(count)
    log_path = system_globals.OWLSM_OUTPUT_LOG
    assert log_path.exists(), f"Output log does not exist: {log_path}"

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    found = sum(1 for line in lines if _is_valid_error_line(line))
    assert found >= need, f"Expected at least {need} valid error JSON line(s), found {found}"


def _is_valid_error_line(line: str) -> bool:
    line = line.strip()
    if not line:
        return False
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return False
    if not isinstance(obj, dict):
        return False
    if "type" in obj and "action" in obj:
        return False
    if "error_code" not in obj or "location" not in obj or "details" not in obj:
        return False
    if not isinstance(obj.get("error_code"), int):
        return False
    if not isinstance(obj.get("location"), str) or not isinstance(obj.get("details"), str):
        return False
    return True


@given(parsers.parse('I remove owLSM output log'))
@when(parsers.parse('I remove owLSM output log'))
@then(parsers.parse('I remove owLSM output log'))
def I_remove_owlsm_output_log():
    try:
        if os.path.exists(system_globals.OWLSM_OUTPUT_LOG):
            os.remove(system_globals.OWLSM_OUTPUT_LOG)
        logger.log_info(f"Successfully removed owLSM output log: {system_globals.OWLSM_OUTPUT_LOG}")
    except Exception as e:
        logger.log_error(f"Failed to remove owLSM output log: {system_globals.OWLSM_OUTPUT_LOG}. Error: {e}")
        assert False, f"Failed to remove owLSM output log: {system_globals.OWLSM_OUTPUT_LOG}. Error: {e}"