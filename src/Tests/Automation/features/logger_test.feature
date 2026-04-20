Feature: logger tests

Scenario: owLSM_log_contains_starting_message
    Given The owLSM process is running
    Then I ensure owLSM log contains "Starting OWLSM. Version:"

Scenario: owLSM_log_location_config
    Given The owLSM process is running
    When I stop the owLSM process
    And The owLSM process is not running
    And I ensure the file "/tmp/owlsm_custom_location.log" does not exist
    And I ensure the owLSM default log does not exist
    And I start the owLSM process with config file "log_location_config.json"
    And The owLSM process is running
    Then The owLSM default log should not exist
    And I ensure the file "/tmp/owlsm_custom_location.log" exists
    And I ensure the file "/tmp/owlsm_custom_location.log" has content
    And I ensure the file "/tmp/owlsm_custom_location.log" contains "Starting OWLSM. Version:"
    And I stop the owLSM process
    And The owLSM process is not running
    And I ensure the file "/tmp/owlsm_custom_location.log" does not exist
    And I start the owLSM process
    And The owLSM process is running