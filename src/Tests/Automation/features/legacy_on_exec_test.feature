Feature: Legacy on exec tests

Scenario: legacy_allowed_exec
    Given I stop the owLSM process
    And The owLSM process is not running
    When I start the owLSM process with config file "legacy_exec_config.json"
    And The owLSM process is running
    And I run the command "/usr/bin/ls -l /tmp" sync
    Then I find the event in output in "30" seconds:
        | process.ppid                      | <automation_pid>         |
        | action                            | ALLOW_EVENT              |
        | type                              | EXEC                     |
        | process.file.path                 | <automation_binary_path> |
        | parent_process.file.path          | <automation_binary_path> |
        | parent_process.pid                | <automation_pid>         |
        | parent_process.file.type          | REGULAR_FILE             |
        | data.target.process.file.path     | /usr/bin/ls              |
        | data.target.process.file.filename | ls                       |
        | data.target.process.cmd           | /usr/bin/ls -l /tmp      |


Scenario: legacy_blocked_exec_alerts_without_blocking
    Given The owLSM process is running
    When I run the command "/usr/bin/ls -lAa /tmp" sync
    Then I find the event in output in "30" seconds:
        | process.ppid                    | <automation_pid>         |
        | action                          | BLOCK_EVENT              |
        | type                            | EXEC                     |
        | process.file.path               | <automation_binary_path> |
        | data.target.process.file.path   | /usr/bin/ls              |
        | data.target.process.cmd         | /usr/bin/ls -lAa /tmp    |
        | matched_rule_id                 | 8                        |


Scenario: legacy_complex_exec_rule__match_one_event_dont_match_other_events_due_to_not_and_condition
    Given The owLSM process is running
    When I run the command "/usr/bin/echo complex_exec_test" sync
    And I run the command "/usr/bin/echo complex_exec_excluded" sync
    And I run the command "/usr/bin/echo matching_only_2_of" sync
    Then I find the event in output in "30" seconds:
        | process.ppid                  | <automation_pid>                |
        | action                        | BLOCK_EVENT                     |
        | type                          | EXEC                            |
        | process.file.path             | <automation_binary_path>        |
        | data.target.process.file.path | /usr/bin/echo                   |
        | data.target.process.cmd       | /usr/bin/echo complex_exec_test |
        | matched_rule_id               | 2                               |
    And I find the event in output in "10" seconds:
        | action                        | ALLOW_EVENT                         |
        | type                          | EXEC                                |
        | process.file.path             | <automation_binary_path>            |
        | data.target.process.file.path | /usr/bin/echo                       |
        | data.target.process.cmd       | /usr/bin/echo complex_exec_excluded |
        | matched_rule_id               | 0                                   |
    And I find the event in output in "10" seconds:
        | action                        | ALLOW_EVENT                      |
        | type                          | EXEC                             |
        | process.file.path             | <automation_binary_path>         |
        | data.target.process.file.path | /usr/bin/echo                    |
        | data.target.process.cmd       | /usr/bin/echo matching_only_2_of |
        | matched_rule_id               | 0                                |
    And I stop the owLSM process
    And The owLSM process is not running
    And I start the owLSM process
