from __future__ import annotations

from pathlib import Path
import shutil

from Utils.cluster_utils import get_cluster
from Utils.logger_utils import logger
from Utils.owlsm_utils import copy_owlsm_logger_log
from globals.global_strings import global_strings


def clear_owlsm_log_and_output() -> None:
    if global_strings.LOG_PATH.is_file():
        _truncate_file(global_strings.LOG_PATH)
    if global_strings.OWLSM_OUTPUT_LOG.is_file():
        _truncate_file(global_strings.OWLSM_OUTPUT_LOG)


def save_log_files(scenario_name: str) -> None:
    try:
        copy_owlsm_logger_log()
    except Exception as e:
        logger.log_error(f"Failed to copy owlsm logger log: {e}")
    try:
        log_storage_path = (
            Path(global_strings.LOG_STORAGE_PATH)
            / global_strings.TESTS_START_TIME
            / scenario_name
        )
        log_storage_path.mkdir(parents=True, exist_ok=True)
        _copy_if_exists(global_strings.LOG_PATH, log_storage_path)
        _copy_if_exists(global_strings.OWLSM_OUTPUT_LOG, log_storage_path)
        _copy_if_exists(global_strings.OWLSM_LOGGER_LOG, log_storage_path)
        for node_log in global_strings.AUTOMATION_ROOT_DIR.glob("owlsm.*.log"):
            _copy_if_exists(node_log, log_storage_path)
        logger.log_info(f"Saved log files to {log_storage_path}")
    except Exception as e:
        logger.log_error(f"Failed to save log files: {e}")


def remove_old_log_directories() -> None:
    try:
        log_storage_path = Path(global_strings.LOG_STORAGE_PATH)
        if not log_storage_path.exists() or not log_storage_path.is_dir():
            return
        directories = [d for d in log_storage_path.iterdir() if d.is_dir()]
        if len(directories) <= 5:
            return
        directories.sort(key=lambda item: item.stat().st_mtime)
        oldest_dir = directories[0]
        shutil.rmtree(oldest_dir)
        logger.log_info(f"Removed oldest log directory: {oldest_dir}")
    except Exception as e:
        logger.log_error(f"Failed to cleanup old log directories: {e}")


def count_owlsm_log_messages(needles: list[str]) -> dict[str, tuple[int, list[str]]]:
    node_name, text = _read_main_node_owlsm_logger()
    results: dict[str, tuple[int, list[str]]] = {}
    for needle in needles:
        count = 0
        samples: list[str] = []
        for line in text.splitlines():
            found = line.count(needle)
            if found == 0:
                continue
            count += found
            if len(samples) < 5:
                samples.append(f"{node_name}: {line.strip()}")
        results[needle] = (count, samples)
    return results


def _read_main_node_owlsm_logger() -> tuple[str, str]:
    node_name = get_cluster().main_node.name
    copy_owlsm_logger_log()
    text = global_strings.OWLSM_LOGGER_LOG.read_text(encoding="utf-8", errors="ignore")
    logger.log_info(f"owlsm logger on {node_name} is {len(text.splitlines())} lines")
    return node_name, text


def _truncate_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"log file not found: {path}")
    with open(path, "w", encoding="utf-8"):
        pass


def _copy_if_exists(source: Path, dest_dir: Path) -> None:
    if source.exists():
        shutil.copy(source, dest_dir / source.name)
