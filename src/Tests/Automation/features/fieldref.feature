Feature: Fieldref matching tests

Scenario: chmod_blocked_with_multiple_numeric_and_string_fieldrefs
    Given The owLSM process is running
    And I ensure the file "/tmp/fieldref_chmod_test" exists
    And I run the command "/usr/bin/chmod 644 /tmp/fieldref_chmod_test" sync
    When I run the command "/usr/bin/chmod 755 /tmp/fieldref_chmod_test" sync
    Then I find the event in output in "30" seconds:
        | process.ppid                      | <automation_pid>                                                          |
        | action                            | BLOCK_EVENT                                                               |
        | type                              | CHMOD                                                                     |
        | process.file.path                 | /usr/bin/chmod                                                            |
        | process.file.filename             | chmod                                                                     |
        | process.cmd                       | /usr/bin/chmod 755 /tmp/fieldref_chmod_test                               |
        | data.target.file.path             | /tmp/fieldref_chmod_test                                                  |
        | data.target.file.filename         | fieldref_chmod_test                                                       |
        | data.chmod.requested_mode         | 493                                                                       |
        | matched_rule_id                   | 37                                                                        |
        | matched_rule_metadata.description | Fieldref automation test - CHMOD with 3 string and 3 numeric fieldrefs    |
        | matched_rule_metadata.title       | Fieldref CHMOD metadata title                                             |
        | matched_rule_metadata.severity    | high                                                                      |
        | matched_rule_metadata.mitre_tags  | ['attack.execution', 'attack.t1059.004']                                  |
        | matched_rule_metadata.name        | fieldref_chmod_rule                                                       |
        | matched_rule_metadata.author      | Automation Team                                                           |
        | matched_rule_metadata.status      | test                                                                      |


Scenario: rename_blocked_with_multiple_numeric_and_string_fieldrefs
    Given The owLSM process is running
    And I ensure the file "/tmp/fieldref_rename_src" exists
    And I run the command "/usr/bin/chmod 644 /tmp/fieldref_rename_src" sync
    And I ensure the file "/tmp/fieldref_rename_dst" exists
    And I run the command "/usr/bin/chmod 755 /tmp/fieldref_rename_dst" sync
    When I run the command "/usr/bin/mv /tmp/fieldref_rename_src /tmp/fieldref_rename_dst" sync
    And The file "/tmp/fieldref_rename_src" should exist "true"
    Then I find the event in output in "30" seconds:
        | process.ppid                      | <automation_pid>                                                                                        |
        | action                            | BLOCK_EVENT                                                                                             |
        | type                              | RENAME                                                                                                  |
        | process.file.path                 | /usr/bin/mv                                                                                             |
        | data.rename.source_file.path      | /tmp/fieldref_rename_src                                                                                |
        | data.rename.destination_file.path | /tmp/fieldref_rename_dst                                                                                |
        | matched_rule_id                   | 38                                                                                                      |
        | matched_rule_metadata.description | Fieldref automation test - RENAME with 2 string and 2 numeric fieldrefs using source/destination fields |
        | matched_rule_metadata.title       | Fieldref RENAME metadata title                                                                          |
        | matched_rule_metadata.severity    | medium                                                                                                  |
        | matched_rule_metadata.mitre_tags  | ['attack.defense-evasion', 'attack.t1070.010']                                                          |
        | matched_rule_metadata.name        | fieldref_rename_rule                                                                                    |
        | matched_rule_metadata.author      | Automation Team                                                                                         |
        | matched_rule_metadata.status      | None                                                                                                    |
