from pytest_bdd import given, parsers, then, when

from Utils.cluster_utils import get_cluster, get_pod, get_test_pod, pods_in_manifest
from Utils.file_utils import File, chmod_file, create_file


@given(parsers.parse('I ensure the file "{filepath}" exists on main_node'))
@when(parsers.parse('I ensure the file "{filepath}" exists on main_node'))
@then(parsers.parse('I ensure the file "{filepath}" exists on main_node'))
def i_ensure_the_file_exists_on_main_node(filepath):
    create_file(_main_node_file(filepath))


@given(parsers.parse('I chmod the file "{filepath}" to "{mode}" on main_node'))
@when(parsers.parse('I chmod the file "{filepath}" to "{mode}" on main_node'))
@then(parsers.parse('I chmod the file "{filepath}" to "{mode}" on main_node'))
def i_chmod_the_file_on_main_node(filepath, mode):
    chmod_file(_main_node_file(filepath, int(mode, 8)))


@given(parsers.parse('I ensure the file "{filepath}" exists in the test_pod'))
@when(parsers.parse('I ensure the file "{filepath}" exists in the test_pod'))
@then(parsers.parse('I ensure the file "{filepath}" exists in the test_pod'))
def i_ensure_the_file_exists_in_the_test_pod(filepath):
    create_file(_test_pod_file(filepath))


@given(parsers.parse('I chmod the file "{filepath}" to "{mode}" in the test_pod'))
@when(parsers.parse('I chmod the file "{filepath}" to "{mode}" in the test_pod'))
@then(parsers.parse('I chmod the file "{filepath}" to "{mode}" in the test_pod'))
def i_chmod_the_file_in_the_test_pod(filepath, mode):
    chmod_file(_test_pod_file(filepath, int(mode, 8)))


@given(parsers.parse('I chmod the file "{filepath}" to "{mode}" in every pod from "{manifest}"'))
@when(parsers.parse('I chmod the file "{filepath}" to "{mode}" in every pod from "{manifest}"'))
@then(parsers.parse('I chmod the file "{filepath}" to "{mode}" in every pod from "{manifest}"'))
def i_chmod_the_file_in_every_pod_from_manifest(filepath, mode, manifest):
    permissions = int(mode, 8)
    for pod in pods_in_manifest(manifest):
        create_file(File(path=filepath, target=pod))
        chmod_file(File(path=filepath, permissions=permissions, target=pod))


@given(parsers.parse('I chmod the file "{filepath}" to "{mode}" in pod "{alias}"'))
@when(parsers.parse('I chmod the file "{filepath}" to "{mode}" in pod "{alias}"'))
@then(parsers.parse('I chmod the file "{filepath}" to "{mode}" in pod "{alias}"'))
def i_chmod_the_file_in_pod(filepath, mode, alias):
    pod = get_pod(alias)
    permissions = int(mode, 8)
    create_file(File(path=filepath, target=pod))
    chmod_file(File(path=filepath, permissions=permissions, target=pod))


def _main_node_file(filepath: str, permissions: int = 0) -> File:
    return File(path=filepath, permissions=permissions, target=get_cluster().main_node)


def _test_pod_file(filepath: str, permissions: int = 0) -> File:
    return File(path=filepath, permissions=permissions, target=get_test_pod())
