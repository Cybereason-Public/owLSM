from pytest_bdd import scenario
from common_steps.file_steps import *
from common_steps.process_steps import *
from common_steps.event_steps import *
from common_steps.network_steps import *
from common_steps.logger_steps import *
from common_steps.db_steps import *

@scenario('on_chmod_test.feature', 'allowed_chmod')
def test_allowed_chmod():
    pass

@scenario('on_chmod_test.feature', 'blocked_chmod_when_config_is_passed_via_stdin')
def test_blocked_chmod_when_config_is_passed_via_stdin():
    pass

@scenario('on_chmod_test.feature', 'blocked_chmod')
def test_blocked_chmod():
    pass

@scenario('on_chmod_test.feature', 'blocked_and_kill_process_chmod')
def test_blocked_and_kill_process_chmod():
    pass

@scenario('on_chmod_test.feature', 'blocked_and_kill_parent_chmod')
def test_blocked_and_kill_parent_chmod():
    pass

@scenario('on_chmod_test.feature', 'blocked_chmod_directory')
def test_blocked_chmod_directory():
    pass

@scenario('on_chmod_test.feature', 'complex_chmod_rule__match_one_event_dont_match_other_events_due_to_not_and_condition')
def test_complex_chmod_rule__match_one_event_dont_match_other_events_due_to_not_and_condition():
    pass

@scenario('on_chmod_test.feature', 'two_rules_match_same_event')
def test_two_rules_match_same_event():
    pass

@scenario('on_chmod_test.feature', 'escaped_wildcards_in_string')
def test_escaped_wildcards_in_string():
    pass

@scenario('on_chmod_test.feature', 'all_wildcards_in_rule')
def test_all_wildcards_in_rule():
    pass

@scenario('on_chmod_test.feature', 'out_of_range_versions')
def test_out_of_range_versions():
    pass

@scenario('on_chmod_test.feature', 'complex_120_token_chmod_rule__match_and_exclude')
def test_complex_120_token_chmod_rule__match_and_exclude():
    pass

@scenario('on_chmod_test.feature', 'neq_modifier_numeric_and_string_exclusion')
def test_neq_modifier_numeric_and_string_exclusion():
    pass

@scenario('on_chmod_test.feature', 'regex_chmod_rule_match')
def test_regex_chmod_rule_match():
    pass

@scenario('on_chown_test.feature', 'allowed_chown')
def test_allowed_chown():
    pass

@scenario('on_chown_test.feature', 'blocked_chown')
def test_blocked_chown():
    pass

@scenario('on_fork_test.feature', 'allowed_fork')
def test_allowed_fork():
    pass

@scenario('on_exit_test.feature', 'allowed_exit')
def test_allowed_exit():
    pass

@scenario('on_exec_test.feature', 'allowed_exec')
def test_allowed_exec():
    pass

@scenario('on_exec_test.feature', 'blocked_exec')
def test_blocked_exec():
    pass

@scenario('on_exec_test.feature', 'complex_exec_rule__match_one_event_dont_match_other_events_due_to_not_and_condition')
def test_complex_exec_rule__match_one_event_dont_match_other_events_due_to_not_and_condition():
    pass

@scenario('on_file_create.feature', 'allowed_file_create')
def test_allowed_file_create():
    pass

@scenario('on_file_create.feature', 'blocked_file_create')
def test_blocked_file_create():
    pass

@scenario('on_write_test.feature', 'allowed_write')
def test_allowed_write():
    pass

@scenario('on_write_test.feature', 'blocked_write')
def test_blocked_write():
    pass

@scenario('on_read_test.feature', 'allowed_read')
def test_allowed_read():
    pass

@scenario('on_read_test.feature', 'blocked_read')
def test_blocked_read():
    pass

@scenario('on_unlink_test.feature', 'allowed_unlink')
def test_allowed_unlink():
    pass

@scenario('on_unlink_test.feature', 'blocked_unlink')
def test_blocked_unlink():
    pass

@scenario('on_rename_test.feature', 'allowed_rename')
def test_allowed_rename():
    pass

@scenario('on_rename_test.feature', 'blocked_rename')
def test_blocked_rename():
    pass

@scenario('on_file_create.feature', 'excluded_file_create')
def test_excluded_file_create():
    pass

@scenario('on_mkdir.feature', 'allowed_mkdir')
def test_allowed_mkdir():
    pass

@scenario('on_mkdir.feature', 'blocked_mkdir')
def test_blocked_mkdir():
    pass

@scenario('on_mkdir.feature', 'excluded_mkdir')
def test_excluded_mkdir():
    pass

@scenario('on_rmdir.feature', 'allowed_rmdir')
def test_allowed_rmdir():
    pass

@scenario('on_rmdir.feature', 'blocked_rmdir')
def test_blocked_rmdir():
    pass

@scenario('on_rmdir.feature', 'excluded_rmdir')
def test_excluded_rmdir():
    pass

@scenario('on_mkdir.feature', 'mkdir_and_rmdir_directory_tree')
def test_mkdir_and_rmdir_directory_tree():
    pass

@scenario('stdio_types_test.feature', 'allowed_stdio_redirection')
def test_allowed_stdio_redirection():
    pass

@scenario('life_cycle_test.feature', 'restart_owlsm_twice')
def test_restart_owlsm_twice():
    pass

@scenario('life_cycle_test.feature', 'owlsm_cleans_maps')
def test_owlsm_cleans_maps():
    pass

@scenario('ignored_events.feature', 'related_processes_are_ignored')
def test_related_processes_are_ignored():
    pass

@scenario('ignored_events.feature', 'cached_write_event_reported_only_once')
def test_cached_write_event_reported_only_once():
    pass

@scenario('ignored_events.feature', 'read_event_disabled_in_config')
def test_read_event_disabled_in_config():
    pass

@scenario('logger_test.feature', 'owLSM_log_contains_starting_message')
def test_owLSM_log_contains_starting_message():
    pass

@scenario('logger_test.feature', 'owLSM_log_location_config')
def test_owLSM_log_location_config():
    pass

@scenario('keywords_rules.feature', 'keyword_with_all_modifier')
def test_keyword_with_all_modifier():
    pass

@scenario('keywords_rules.feature', 'multi_keyword_rule')
def test_multi_keyword_rule():
    pass

@scenario('keywords_rules.feature', 'multi_event_keyword_rule')
def test_multi_event_keyword_rule():
    pass

@scenario('on_tcp_test.feature', 'allowed_http_connection')
def test_allowed_http_connection():
    pass

@scenario('on_tcp_test.feature', 'blocked_http_connection')
def test_blocked_http_connection():
    pass

@scenario('on_tcp_test.feature', 'allowed_https_connection')
def test_allowed_https_connection():
    pass

@scenario('on_tcp_test.feature', 'allowed_ssh_connection')
def test_allowed_ssh_connection():
    pass

@scenario('on_tcp_test.feature', 'allowed_sftp_connection')
def test_allowed_sftp_connection():
    pass

@scenario('on_tcp_test.feature', 'allowed_netcat_connection')
def test_allowed_netcat_connection():
    pass

@scenario('on_tcp_test.feature', 'blocked_incoming_netcat_connection')
def test_blocked_incoming_netcat_connection():
    pass

@scenario('on_tcp_test.feature', 'blocked_outgoing_netcat_connection')
def test_blocked_outgoing_netcat_connection():
    pass

@scenario('shell_commands.feature', 'multiple_unchained_shell_commands_same_shell_instance')
def test_multiple_unchained_shell_commands_same_shell_instance():
    pass

@scenario('shell_commands.feature', 'chained_shell_command_find_all_events')
def test_chained_shell_command_find_all_events():
    pass

@scenario('shell_commands.feature', 'mixed_shell_builtin_and_external_commands')
def test_mixed_shell_builtin_and_external_commands():
    pass

@scenario('shell_commands.feature', 'shell_exits_before_child_process')
def test_shell_exits_before_child_process():
    pass

@scenario('shell_commands.feature', 'shell_exec_to_another_process')
def test_shell_exec_to_another_process():
    pass

@scenario('shell_commands.feature', 'shell_starts_before_owlsm')
def test_shell_starts_before_owlsm():
    pass

@scenario('shell_commands.feature', 'new_shell_gets_detected_and_monitored')
def test_new_shell_gets_detected_and_monitored():
    pass

@scenario('shell_commands.feature', 'complex_commands')
def test_complex_commands():
    pass

@scenario('shell_commands.feature', 'shell_db_contains_all_system_shells')
def test_shell_db_contains_all_system_shells():
    pass

@scenario('shell_commands.feature', 'shell_monitoring_disabled')
def test_shell_monitoring_disabled():
    pass

@scenario('shell_commands.feature', 'shell_command_blocked_write')
def test_shell_command_blocked_write():
    pass

@scenario('fieldref.feature', 'chmod_blocked_with_multiple_numeric_and_string_fieldrefs')
def test_chmod_blocked_with_multiple_numeric_and_string_fieldrefs():
    pass

@scenario('fieldref.feature', 'rename_blocked_with_multiple_numeric_and_string_fieldrefs')
def test_rename_blocked_with_multiple_numeric_and_string_fieldrefs():
    pass

@scenario('placeholders.feature', 'placeholder_expand_all_three_fields_match_blocks_chmod')
def test_placeholder_expand_all_three_fields_match_blocks_chmod():
    pass

@scenario('placeholders.feature', 'placeholder_expand_two_of_three_fields_match_allows_chmod')
def test_placeholder_expand_two_of_three_fields_match_allows_chmod():
    pass

@scenario('flatbuffer.feature', 'flatbuffer_output_events_and_errors')
def test_flatbuffer_output_events_and_errors():
    pass