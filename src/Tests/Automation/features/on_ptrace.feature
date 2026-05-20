Feature: Anti-tampering ptrace protection

Scenario: ptrace_protection_disabled
    Given The owLSM process is running
    When I run the command "timeout 0.2 strace -p $(pgrep -nx sshd) 2>/dev/null || true" sync
    Then I dont find the event in output in "10" seconds:
        | type | PTRACE |


Scenario: ptrace_on_protected_process_is_blocked
    Given The owLSM process is running
    When I stop the owLSM process
    And The owLSM process is not running
    And I run the resource "ptrace_attacher" with arguments "" async and save pid
    And I start owLSM with anti_tampering config and protect the programs "none" and "none"
    And I write the running owLSM PID to the resource "ptrace_attacher" process stdin
    And I sleep for "2" seconds
    Then I find the event in output in "10" seconds:
        | type                              | PTRACE                              |
        | action                            | BLOCK_EVENT                         |
        | process.file.filename             | strace                              |
        | data.target.process.file.filename | owlsm                               |
    And I stop the owLSM process
    And The owLSM process is not running
    And I start the owLSM process
    And The owLSM process is running
