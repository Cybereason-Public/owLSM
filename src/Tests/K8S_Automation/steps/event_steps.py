import json
import time

import jmespath
from pytest_bdd import given, parsers, then, when

from Utils.cluster_utils import get_cluster
from Utils.logger_utils import logger
from globals.global_strings import global_strings


@given(parsers.parse('I find the event in output in "{duration}" seconds:'))
@when(parsers.parse('I find the event in output in "{duration}" seconds:'))
@then(parsers.parse('I find the event in output in "{duration}" seconds:'))
def i_find_the_event_in_output(datatable, duration):
    success, expected = is_event_in_output(datatable, duration)
    assert success, f"Event not found in output: {expected}"


@given(parsers.parse('I dont find the event in output in "{duration}" seconds:'))
@when(parsers.parse('I dont find the event in output in "{duration}" seconds:'))
@then(parsers.parse('I dont find the event in output in "{duration}" seconds:'))
def i_dont_find_the_event_in_output(datatable, duration):
    success, expected = is_event_in_output(datatable, duration)
    assert not success, f"Event found in output: {expected}"


def is_event_in_output(datatable, duration) -> tuple[bool, dict]:
    duration = int(duration)
    expected = {row[0].strip(): row[1].strip() for row in datatable}
    expected = process_dynamic_placeholders(expected)
    start_time = time.time()
    failed_to_parse_indexes = set()
    log_path = global_strings.OWLSM_OUTPUT_LOG
    while time.time() - start_time < duration:
        if not log_path.is_file():
            time.sleep(0.1)
            continue
        with log_path.open("r", encoding="utf-8", errors="ignore") as f:
            index = 0
            for line in f:
                try:
                    line = line.strip()
                    index += 1
                    event = json.loads(line)
                    if all(
                        str(jmespath.search(key, event)).strip() == str(value).strip()
                        for key, value in expected.items()
                    ):
                        logger.log_info(f"Found event in output: {line}")
                        return True, expected
                except Exception as e:
                    if index not in failed_to_parse_indexes:
                        logger.log_error(f"Error parsing line {index}: '{line}' \n{e}")
                        failed_to_parse_indexes.add(index)
    logger.log_error(f"Event not found in output: {expected}")
    return False, expected


def process_dynamic_placeholders(data: dict) -> dict:
    replacements = {
        "<main_node_name>": get_cluster().main_node.name,
    }
    for alias, pod in get_cluster().main_node.pods_by_alias.items():
        replacements[f"<{alias}_name>"] = pod.name
        replacements[f"<{alias}_namespace>"] = pod.namespace
        replacements[f"<{alias}_uid>"] = pod.uid
        replacements[f"<{alias}_label_app>"] = pod.labels.get("app", "")
        replacements[f"<{alias}_container_id>"] = _container_id_u64(pod.container_id)
    processed = {}
    for key, value in data.items():
        for placeholder, replacement in replacements.items():
            if placeholder in value:
                value = value.replace(placeholder, replacement)
                logger.log_info(f"Replaced placeholder '{placeholder}' with '{replacement}'")
        processed[key] = value
    return processed


def _container_id_u64(container_id: str) -> str:
    stripped = container_id.split("://", 1)[-1]
    if len(stripped) < 16:
        raise RuntimeError(f"container id is too short: {container_id}")
    try:
        return str(int(stripped[:16], 16))
    except ValueError as e:
        raise RuntimeError(f"container id is not hex: {container_id}") from e
