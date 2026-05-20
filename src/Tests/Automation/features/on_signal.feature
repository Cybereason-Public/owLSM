Feature: Anti-tampering signal protection

Scenario: signal_protection_disabled_sigkill_kills_owlsm
    Given The owLSM process is running
    And I run the resource "protected_process" with arguments "" async and save pid
    When I run the command "/usr/bin/pkill -9 protected_process" sync
    And I send SIGKILL to owLSM
    Then The owLSM process is not running
    And I dont find the event in output in "5" seconds:
        | type | SIGNAL |
    And I start the owLSM process


Scenario: signal_protection_enabled_sigkill_blocked
    Given The owLSM process is running
    When I stop the owLSM process
    And The owLSM process is not running
    And I run the resource "protected_process" with arguments "" async and save pid
    And I run the resource "signal_sender" with arguments "" async and save pid
    And I start owLSM with anti_tampering config and protect the programs "protected_process" and "none"
    And signal_sender sends signal to protected_process
    Then I find the event in output in "10" seconds:
        | type                              | SIGNAL                              |
        | action                            | BLOCK_EVENT                         |
        | process.file.filename             | signal_sender                       |
        | data.target.process.file.filename | protected_process                   |
        | data.signal                       | 9                                   |
    And I find the event in output in "10" seconds:
        | type                  | SIGNAL        |
        | action                | BLOCK_EVENT   |
        | process.file.filename | signal_sender |
        | data.signal           | 11            |
    And I find the event in output in "10" seconds:
        | type                              | SIGNAL                              |
        | action                            | BLOCK_EVENT                         |
        | process.file.filename             | signal_sender                       |
        | data.target.process.file.filename | protected_process                   |
        | data.signal                       | 6                                   |


Scenario: protected_process_kills_a_protected_process
    Given The owLSM process is running
    When I stop the owLSM process
    And The owLSM process is not running
    And I run the resource "protected_process" with arguments "" async and save pid
    And I run the resource "signal_sender" with arguments "" async and save pid
    And I start owLSM with anti_tampering flatbuffers config and protect the programs "protected_process" and "signal_sender"
    And I run flatbuffer_reader async for "events" stream and save pid
    And signal_sender sends signal to protected_process
    And I ensure the resource "protected_process" subprocess has exited
    And I ensure the resource "signal_sender" subprocess has exited
    Then I dont find the event in output in "10" seconds:
        | type                  | SIGNAL        |
        | process.file.filename | signal_sender |


Scenario: oom_kills_protected_process
    Given The owLSM process is running
    When I stop the owLSM process
    And The owLSM process is not running
    And I run the resource "OOM_kill_me" with arguments "" async and save pid
    And I set up the OOM cgroup for the saved resource process
    And I start owLSM with anti_tampering config and protect the programs "OOM_kill_me" and "none"
    And I write "1" to the resource "OOM_kill_me" process stdin
    And I wait until resource "OOM_kill_me" is not running with a timeout of "45" seconds
    And I stop the owLSM process
    And The owLSM process is not running
    And I start the owLSM process
