Feature: Non ASCII character tests

Scenario: different_non_ascii_characters_per_string
    Given The owLSM process is running
    And I ensure new file "/tmp/一二三四五六七八九十" is created
    When I rename the file "/tmp/一二三四五六七八九十" to "/tmp/אבגדהוזחטיכלמנסעפצקר"
    Then I find the event in output in "10" seconds:
        | process.pid                       | <automation_pid>          |
        | type                              | RENAME                    |
        | data.rename.source_file.path      | /tmp/一二三四五六七八九十           |
        | data.rename.destination_file.path | /tmp/אבגדהוזחטיכלמנסעפצקר |


Scenario: mixed_characters
    Given The owLSM process is running
    And I ensure new directory "/tmp/中文字אב😀😁abc" is created
    And I ensure new file "/tmp/中文字אב😀😁abc/גדהו123😂日" is created
    Then I find the event in output in "10" seconds:
        | process.pid           | <automation_pid>          |
        | type                  | FILE_CREATE               |
        | data.target.file.path | /tmp/中文字אב😀😁abc/גדהו123😂日 |


# An emoji is 4 bytes, and the owLSM path string is capped at 256 bytes. /tmp/ (5 bytes) + 31 emojis (124 bytes) + / (1 byte) + 31 emojis (124 bytes) = 254 bytes.
Scenario: short_in_characters_long_in_bytes
    Given The owLSM process is running
    And I ensure new directory "/tmp/😀😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😑😒😓😔😕😖😗😘😙😚😛😜😝😞" is created
    And I ensure new file "/tmp/😀😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😑😒😓😔😕😖😗😘😙😚😛😜😝😞/😟😠😡😢😣😤😥😦😧😨😩😪😫😬😭😮😯😰😱😲😳😴😵😶😷😸😹😺😻😼😽" is created
    Then I find the event in output in "10" seconds:
        | process.pid           | <automation_pid>                                                     |
        | type                  | FILE_CREATE                                                          |
        | data.target.file.path | /tmp/😀😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😑😒😓😔😕😖😗😘😙😚😛😜😝😞/😟😠😡😢😣😤😥😦😧😨😩😪😫😬😭😮😯😰😱😲😳😴😵😶😷😸😹😺😻😼😽 |

Scenario: mixed_characters_flatbuffer
    Given I stop the owLSM process
    And The owLSM process is not running
    When I start the owLSM process with flatbuffers output
    And The owLSM process is running
    And I run flatbuffer_reader async for "events" stream and save pid
    And I ensure new directory "/tmp/中文字אב😀😁abc" is created
    And I ensure new file "/tmp/中文字אב😀😁abc/גדהו123😂日" is created
    Then I find the event in output in "10" seconds:
        | process.pid           | <automation_pid>          |
        | type                  | FILE_CREATE               |
        | data.target.file.path | /tmp/中文字אב😀😁abc/גדהו123😂日 |
    And I check that the async resource process is still running
    And I stop the owLSM process
    And The owLSM process is not running
    And I start the owLSM process
    And The owLSM process is running
