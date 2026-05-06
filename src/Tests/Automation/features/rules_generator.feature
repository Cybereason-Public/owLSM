Feature: RulesGenerator binary tests

Scenario: rules_generator_binary_gets_files_valid
    Given I stop the owLSM process
    And The owLSM process is not running
    And I ensure the file "/tmp/config.json" does not exist
    And I add the path "/tmp/config.json" to the file db
    When I run rules_generator in file mode and write to "/tmp/config.json"
    Then the config at "/tmp/config.json" is valid


Scenario: rules_generator_binary_gets_memory_valid
    Given I stop the owLSM process
    And The owLSM process is not running
    And I ensure the file "/tmp/config.json" does not exist
    And I ensure the file "/tmp/config_memory.json" does not exist
    And I add the path "/tmp/config.json" to the file db
    And I add the path "/tmp/config_memory.json" to the file db
    When I run rules_generator in file mode and write to "/tmp/config.json"
    And I run rules_generator in memory mode and write to "/tmp/config_memory.json"
    Then "/tmp/config.json" and "/tmp/config_memory.json" are identical json files


Scenario: rules_generator_binary_gets_memory_invalid
    Given rules_generator memory mode fails with "duplicate id"
    And rules_generator memory mode fails with "schema validation"
    And rules_generator memory mode fails with "missing placeholder"
    And rules_generator memory mode fails with "bad mapping"
    And rules_generator memory mode fails with "missing id"
    And rules_generator memory mode fails with "fieldref to nonexistent field"
    Then I start the owLSM process
    And The owLSM process is running
