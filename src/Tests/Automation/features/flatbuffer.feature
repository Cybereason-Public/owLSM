Feature: FlatBuffer output format

Scenario: flatbuffer_output_events_and_errors
    Given I stop the owLSM process
    And The owLSM process is not running
    When I start the owLSM process with flatbuffers output
    And The owLSM process is running
    And I run flatbuffer_reader async for "events" stream and save pid
    And I run the command "touch /tmp/owlsm_fb_test2" sync
    And I run the command "/usr/bin/chmod 666 /tmp/owlsm_fb_test2" sync
    And I run the command "/usr/bin/chown root:root /tmp/owlsm_fb_test2" sync
    And I run shell command "wget -q -O /tmp/owlsm_https_probe.dat 'https://example.com/' && rm -f /tmp/owlsm_https_probe.dat" with shell "/bin/bash" and save shell pid
    Then I find the event in output in "30" seconds:
        | process.ppid                      | <automation_pid>                                            |
        | action                            | BLOCK_EVENT                                                 |
        | type                              | CHMOD                                                       |
        | process.file.path                 | /usr/bin/chmod                                              |
        | process.cmd                       | /usr/bin/chmod 666 /tmp/owlsm_fb_test2                      |
        | data.target.file.path             | /tmp/owlsm_fb_test2                                         |
        | data.chmod.requested_mode         | 438                                                         |
        | matched_rule_id                   | 4                                                           |
        | matched_rule_metadata.description | Test rule 4 - CHMOD block with process euid below threshold |
    And I find the event in output in "5" seconds:
        | type                    | EXEC                                         |
        | action                  | ALLOW_EVENT                                  |
        | data.target.process.cmd | /usr/bin/chown root:root /tmp/owlsm_fb_test2 |
    And I find the event in output in "5" seconds:
        | type                          | NETWORK                                                     |
        | action                        | ALLOW_EVENT                                                 |
        | data.network.destination_port | 443                                                         |
        | parent_process.shell_command  | wget -q -O /tmp/owlsm_https_probe.dat 'https://example.com/' && rm -f /tmp/owlsm_https_probe.dat |
    And I check that the async resource process is still running
    And I stop the owLSM process
    And The owLSM process is not running
    And I run flatbuffer_reader async for "errors" stream and save pid
    And I ensure that output file consists of at least "1" valid error message
    And I check that the async resource process is still running
    And I start the owLSM process
    And The owLSM process is running
