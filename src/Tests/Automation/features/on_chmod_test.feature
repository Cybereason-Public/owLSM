Feature: On chmod tests

Scenario: allowed_chmod
    Given The owLSM process is running
    And I ensure the file "/tmp/test1" exists
    When I run the command "/usr/bin/chmod 777 /tmp/test1" sync
    Then I find the event in output in "30" seconds:
        | process.ppid              | <automation_pid>              |
        | action                    | ALLOW_EVENT                   |
        | type                      | CHMOD                         |
        | process.file.path         | /usr/bin/chmod                |
        | process.file.filename     | chmod                         |
        | process.cmd               | /usr/bin/chmod 777 /tmp/test1 |
        | parent_process.file.path  | <automation_binary_path>      |
        | parent_process.pid        | <automation_pid>              |
        | data.target.file.path     | /tmp/test1                    |
        | data.target.file.filename | test1                         |
        | data.chmod.requested_mode | 511                           |
        

Scenario: blocked_chmod
    Given The owLSM process is running
    And I ensure the file "/tmp/test2" exists
    When I run the command "/usr/bin/chmod 666 /tmp/test2" sync
    Then I find the event in output in "30" seconds:
        | process.ppid                      | <automation_pid>                                            |
        | action                            | BLOCK_EVENT                                                 |
        | type                              | CHMOD                                                       |
        | process.file.path                 | /usr/bin/chmod                                              |
        | process.cmd                       | /usr/bin/chmod 666 /tmp/test2                               |
        | data.target.file.path             | /tmp/test2                                                  |
        | data.chmod.requested_mode         | 438                                                         |
        | matched_rule_id                   | 4                                                           |
        | matched_rule_metadata.description | Test rule 4 - CHMOD block with process euid below threshold |


Scenario: blocked_and_kill_process_chmod
    Given The owLSM process is running
    And I ensure the file "/tmp/test3" exists
    When I run the command "/usr/bin/chmod 555 /tmp/test3" sync
    Then I find the event in output in "30" seconds:
        | action                    | BLOCK_KILL_PROCESS            |
        | type                      | CHMOD                         |
        | process.file.path         | /usr/bin/chmod                |
        | process.cmd               | /usr/bin/chmod 555 /tmp/test3 |
        | data.target.file.path     | /tmp/test3                    |
        | data.chmod.requested_mode | 365                           |
        | matched_rule_id           | 5                             |
    And I find the event in output in "30" seconds:
        | action                            | ALLOW_EVENT                   |
        | process.ppid                      | <automation_pid>              |
        | process.file.path                 | /usr/bin/chmod                |
        | type                              | EXIT                          |
        | process.cmd                       | /usr/bin/chmod 555 /tmp/test3 |
        | data.exit_code                    | 0                             |
        | data.signal                       | 9                             |
        | matched_rule_metadata.description |                               |


Scenario: blocked_and_kill_parent_chmod
    Given The owLSM process is running
    And I ensure the file "/tmp/test4" exists
    When I run the command "/usr/bin/chmod 444 /tmp/test4" sync as grandchild
    Then I find the event in output in "30" seconds:
        | action                    | BLOCK_KILL_PROCESS_KILL_PARENT |
        | type                      | CHMOD                          |
        | process.file.path         | /usr/bin/chmod                 |
        | process.cmd               | /usr/bin/chmod 444 /tmp/test4  |
        | data.target.file.path     | /tmp/test4                     |
        | data.chmod.requested_mode | 292                            |
        | matched_rule_id           | 6                              |
    And I find the event in output in "30" seconds:
        | action            | ALLOW_EVENT              |
        | process.ppid      | <automation_pid>         |
        | process.file.path | <automation_binary_path> |
        | type              | EXIT                     |
        | data.exit_code    | 0                        |
        | data.signal       | 9                        |


Scenario: blocked_chmod_directory
    Given The owLSM process is running
    And I ensure the directory "/tmp/dir2" exists
    When I run the command "/usr/bin/chmod 666 /tmp/dir2" sync
    Then I find the event in output in "30" seconds:
        | process.ppid              | <automation_pid>             |
        | action                    | BLOCK_EVENT                  |
        | type                      | CHMOD                        |
        | process.file.path         | /usr/bin/chmod               |
        | process.cmd               | /usr/bin/chmod 666 /tmp/dir2 |
        | parent_process.file.path  | <automation_binary_path>     |
        | data.target.file.path     | /tmp/dir2                    |
        | data.chmod.requested_mode | 438                          |
        | data.target.file.type     | DIRECTORY                    |
        | matched_rule_id           | 19                           |


Scenario: complex_chmod_rule__match_one_event_dont_match_other_events_due_to_not_and_condition
    Given The owLSM process is running
    And I ensure the file "/tmp/test3" exists
    And I ensure the file "/tmp/complex_test" exists
    And I ensure the file "/tmp/complex_excluded" exists
    And I run the command "/usr/bin/chown automation_test_user:automation_test_user /tmp/complex_test" sync
    And I run the command "/usr/bin/chown automation_test_user:automation_test_user /tmp/complex_excluded" sync
    When I run the command "/usr/bin/chmod 755 /tmp/complex_test" sync as grandchild as user "automation_test_user"
    And I run the command "/usr/bin/chmod 755 /tmp/complex_excluded" sync as grandchild as user "automation_test_user"
    And I run the command "/usr/bin/chmod 777 /tmp/test3" sync as grandchild as user "automation_test_user"
    Then I find the event in output in "30" seconds:
        | action                    | BLOCK_EVENT       |
        | type                      | CHMOD             |
        | process.file.path         | /usr/bin/chmod    |
        | data.target.file.path     | /tmp/complex_test |
        | data.chmod.requested_mode | 493               |
        | matched_rule_id           | 1                 |
    And I find the event in output in "10" seconds:
        | action                    | ALLOW_EVENT           |
        | type                      | CHMOD                 |
        | process.file.path         | /usr/bin/chmod        |
        | data.target.file.path     | /tmp/complex_excluded |
        | data.chmod.requested_mode | 493                   |
        | matched_rule_id           | 0                     |
    And I find the event in output in "10" seconds:
        | action                    | ALLOW_EVENT    |
        | type                      | CHMOD          |
        | process.file.path         | /usr/bin/chmod |
        | data.target.file.path     | /tmp/test3     |
        | data.chmod.requested_mode | 511            |
        | matched_rule_id           | 0              |


Scenario: two_rules_match_same_event
    Given The owLSM process is running
    And I ensure the file "/tmp/ordering_check" exists
    And I ensure the file "/tmp/ordering_check_skip_first" exists
    When I run the command "/usr/bin/chmod 700 /tmp/ordering_check" sync
    Then I dont find the event in output in "10" seconds:
        | type        | CHMOD                                  |
        | process.cmd | /usr/bin/chmod 700 /tmp/ordering_check |
    And I run the command "/usr/bin/chmod 700 /tmp/ordering_check_skip_first" sync
    And I find the event in output in "30" seconds:
        | process.ppid              | <automation_pid>                                  |
        | action                    | BLOCK_EVENT                                       |
        | type                      | CHMOD                                             |
        | process.file.path         | /usr/bin/chmod                                    |
        | process.cmd               | /usr/bin/chmod 700 /tmp/ordering_check_skip_first |
        | data.target.file.path     | /tmp/ordering_check_skip_first                    |
        | data.chmod.requested_mode | 448                                               |
        | matched_rule_id           | 21                                                |


Scenario: escaped_wildcards_in_string
    Given The owLSM process is running
    And I ensure the file "/tmp/escaped*wildcards?test" exists
    When I run the command "/usr/bin/chmod 700 /tmp/escaped*wildcards?test" sync
    Then I find the event in output in "20" seconds:
        | action                | BLOCK_EVENT                 |
        | type                  | CHMOD                       |
        | process.file.path     | /usr/bin/chmod              |
        | data.target.file.path | /tmp/escaped*wildcards?test |
        | matched_rule_id       | 22                          |



Scenario: all_wildcards_in_rule
    Given The owLSM process is running
    And I ensure the file "/tmp/test_wildcards_automation.txt" exists
    When I run the command "/usr/bin/chmod 700 /tmp/test_wildcards_automation.txt" sync
    Then I find the event in output in "20" seconds:
        | action                | BLOCK_EVENT                       |
        | type                  | CHMOD                             |
        | process.file.path     | /usr/bin/chmod                    |
        | data.target.file.path | /tmp/test_wildcards_automation.txt |
        | matched_rule_id       | 23                                |



Scenario: out_of_range_versions
    Given The owLSM process is running
        And I ensure the file "/tmp/out_of_range_versions_test" exists
        When I run the command "/usr/bin/chmod 700 /tmp/out_of_range_versions_test" sync
        Then I dont find the event in output in "10" seconds:
            | type                  | CHMOD                           |
            | data.target.file.path | /tmp/out_of_range_versions_test |
            | matched_rule_id       | 27                              |
        Then I find the event in output in "10" seconds:
            | action                | ALLOW_EVENT                     |
            | type                  | CHMOD                           |
            | data.target.file.path | /tmp/out_of_range_versions_test |
            | matched_rule_id       | 0                               |


Scenario: complex_120_token_chmod_rule__match_and_exclude
    Given The owLSM process is running
    And I ensure the file "/tmp/complex_120_test" exists
    And I ensure the file "/tmp/complex_120_excluded" exists
    When I run the command "/usr/bin/chmod 755 /tmp/complex_120_test" sync
    And I run the command "/usr/bin/chmod 755 /tmp/complex_120_excluded" sync
    Then I find the event in output in "30" seconds:
        | action                            | BLOCK_EVENT                                              |
        | type                              | CHMOD                                                    |
        | process.file.path                 | /usr/bin/chmod                                           |
        | data.target.file.path             | /tmp/complex_120_test                                    |
        | data.chmod.requested_mode         | 493                                                      |
        | matched_rule_id                   | 36                                                       |
        | matched_rule_metadata.description | Complex ~120-token chmod rule for max token limit testing |
    And I find the event in output in "10" seconds:
        | action                    | ALLOW_EVENT               |
        | type                      | CHMOD                     |
        | process.file.path         | /usr/bin/chmod            |
        | data.target.file.path     | /tmp/complex_120_excluded |
        | data.chmod.requested_mode | 493                       |
        | matched_rule_id           | 0                         |


Scenario: neq_modifier_numeric_and_string_exclusion
    Given The owLSM process is running
    And I ensure the file "/tmp/neq_test_file" exists
    When I run the command "/usr/bin/chmod 755 /tmp/neq_test_file" sync
    Then I dont find the event in output in "10" seconds:
        | type                  | CHMOD              |
        | data.target.file.path | /tmp/neq_test_file |
        | matched_rule_id       | 33                 |
    And I dont find the event in output in "10" seconds:
        | type                  | CHMOD              |
        | data.target.file.path | /tmp/neq_test_file |
        | matched_rule_id       | 34                 |
    And I find the event in output in "30" seconds:
        | action                            | BLOCK_EVENT                                  |
        | type                              | CHMOD                                        |
        | process.file.path                 | /usr/bin/chmod                               |
        | data.target.file.path             | /tmp/neq_test_file                           |
        | data.chmod.requested_mode         | 493                                          |
        | matched_rule_id                   | 35                                           |
        | matched_rule_metadata.description | Normal chmod rule matching /tmp/neq_test - no neq |


Scenario: regex_chmod_rule_match
    Given The owLSM process is running
    And I ensure the file "/tmp/regex_alpha" exists
    When I run the command "/usr/bin/chmod 755 /tmp/regex_alpha" sync
    Then I find the event in output in "30" seconds:
        | process.ppid                      | <automation_pid>                                                          |
        | action                            | BLOCK_EVENT                                                               |
        | type                              | CHMOD                                                                     |
        | process.file.path                 | /usr/bin/chmod                                                            |
        | process.file.filename             | chmod                                                                     |
        | data.target.file.path             | /tmp/regex_alpha                                                          |
        | data.target.file.filename         | regex_alpha                                                               |
        | data.chmod.requested_mode         | 493                                                                       |
        | matched_rule_id                   | 51                                                                        |
        | matched_rule_metadata.description | Regex chmod test - multiple regex patterns on different fields             |
