import os
import threading
from datetime import datetime
from enum import Enum
import inspect
from globals.global_strings import global_strings


class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Logger:
    def __init__(self, log_path: str, log_level: LogLevel):
        self.log_path = log_path
        self.log_level = log_level
        self._lock = threading.Lock()

        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        if os.path.exists(log_path):
            os.remove(log_path)

    def _should_log(self, level: LogLevel) -> bool:
        level_order = {
            LogLevel.DEBUG: 0,
            LogLevel.INFO: 1,
            LogLevel.WARNING: 2,
            LogLevel.ERROR: 3,
            LogLevel.CRITICAL: 4
        }
        return level_order[level] >= level_order[self.log_level]

    def _get_caller_info(self):
        frame = inspect.currentframe().f_back.f_back.f_back
        filename = os.path.basename(frame.f_code.co_filename)
        line_number = frame.f_lineno
        return filename, line_number

    def _write_log(self, level: LogLevel, message: str):
        if not self._should_log(level):
            return

        now = datetime.now()
        timestamp = now.strftime("%d.%m.%Y %H:%M:%S.%f")[:-3]
        filename, line_number = self._get_caller_info()
        log_line = f"[{timestamp}][{level.value}] {message}. Location: {filename}:{line_number}\n"
        with self._lock:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(log_line)

    def log_debug(self, message: str):
        self._write_log(LogLevel.DEBUG, message)

    def log_info(self, message: str):
        self._write_log(LogLevel.INFO, message)

    def log_warning(self, message: str):
        self._write_log(LogLevel.WARNING, message)

    def log_error(self, message: str):
        self._write_log(LogLevel.ERROR, message)

    def log_critical(self, message: str):
        self._write_log(LogLevel.CRITICAL, message)


logger = Logger(str(global_strings.LOG_PATH), LogLevel.INFO)
