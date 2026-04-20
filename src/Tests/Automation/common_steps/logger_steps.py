from pytest_bdd import given, when, then, parsers
from globals.system_related_globals import system_globals
import os

@given(parsers.parse('I ensure owLSM log contains "{message}"'))
@when(parsers.parse('I ensure owLSM log contains "{message}"'))
@then(parsers.parse('I ensure owLSM log contains "{message}"'))
def I_ensure_owlsm_log_contains(message):
    with open(system_globals.OWLSM_LOGGER_LOG, 'r') as f:
        assert message in f.read(), f"Message '{message}' not found in owLSM log"

@given("I ensure the owLSM default log does not exist")
@when("I ensure the owLSM default log does not exist")
@then("I ensure the owLSM default log does not exist")
def I_ensure_owlsm_default_log_does_not_exist():
    path = system_globals.OWLSM_LOGGER_LOG
    if os.path.exists(path):
        os.remove(path)
    assert not os.path.exists(path), f"Default owLSM log still exists: {path}"

@given("The owLSM default log should not exist")
@when("The owLSM default log should not exist")
@then("The owLSM default log should not exist")
def the_owlsm_default_log_should_not_exist():
    assert not os.path.exists(system_globals.OWLSM_LOGGER_LOG), \
        f"Default owLSM log exists but should not: {system_globals.OWLSM_LOGGER_LOG}"

@given(parsers.parse('I ensure the file "{filepath}" has content'))
@when(parsers.parse('I ensure the file "{filepath}" has content'))
@then(parsers.parse('I ensure the file "{filepath}" has content'))
def I_ensure_file_has_content(filepath):
    assert os.path.isfile(filepath), f"File does not exist: {filepath}"
    assert os.path.getsize(filepath) > 0, f"File is empty: {filepath}"

@given(parsers.parse('I ensure the file "{filepath}" contains "{message}"'))
@when(parsers.parse('I ensure the file "{filepath}" contains "{message}"'))
@then(parsers.parse('I ensure the file "{filepath}" contains "{message}"'))
def I_ensure_file_contains(filepath, message):
    with open(filepath, 'r') as f:
        assert message in f.read(), f"Message '{message}' not found in file: {filepath}"