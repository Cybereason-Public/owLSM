Feature: owlsm container stress

Scenario: six pods start and exit without kubernetes mapping misses
    Given owlsm is deployed cluster wide
    When I deploy the manifest "six_stress_pods.yaml"
    Then I find the event in output in "30" seconds:
        | type                                 | WRITE                                                                                       |
        | action                               | ALLOW_EVENT                                                                                 |
        | process.cmd                          | /bin/sh -c echo owlsm-stress-write > /tmp/owlsm-stress-write && exec /bin/sleep infinity   |
        | data.target.file.path                | /tmp/owlsm-stress-write                                                                     |
        | data.target.file.filename            | owlsm-stress-write                                                                          |
        | data.target.file.type                | REGULAR_FILE                                                                                |
        | kubernetes.host_event                | False                                                                                       |
        | kubernetes.node_name                 | <main_node_name>                                                                            |
        | kubernetes.pod_name                  | owlsm-stress-write                                                                     |
        | kubernetes.pod_namespace             | owlsm-stress                                                                |
        | kubernetes.pod_uid                   | <write_uid>                                                                      |
        | kubernetes.pod_labels.app            | owlsm-stress-write                                                                |
        | kubernetes.pod_labels."owlsm-automation" | pod |
        | kubernetes.container_id              | <write_container_id>                                                             |
    And I find the event in output in "30" seconds:
        | type                                 | FILE_CREATE                                  |
        | action                               | ALLOW_EVENT                                  |
        | process.cmd                          | /bin/touch /tmp/owlsm-stress-create          |
        | data.target.file.path                | /tmp/owlsm-stress-create                     |
        | data.target.file.filename            | owlsm-stress-create                          |
        | data.target.file.type                | REGULAR_FILE                                 |
        | kubernetes.host_event                | False                                        |
        | kubernetes.node_name                 | <main_node_name>                             |
        | kubernetes.pod_name                  | owlsm-stress-create                     |
        | kubernetes.pod_namespace             | owlsm-stress                |
        | kubernetes.pod_uid                   | <create_uid>                      |
        | kubernetes.pod_labels.app            | owlsm-stress-create                |
        | kubernetes.pod_labels."owlsm-automation" | pod |
        | kubernetes.container_id              | <create_container_id>             |
    And I find the event in output in "30" seconds:
        | type                                 | MKDIR                                  |
        | action                               | ALLOW_EVENT                            |
        | process.cmd                          | /bin/mkdir /tmp/owlsm-stress-mkdir     |
        | data.target.file.path                | /tmp/owlsm-stress-mkdir                |
        | data.target.file.filename            | owlsm-stress-mkdir                     |
        | data.target.file.type                | DIRECTORY                              |
        | kubernetes.host_event                | False                                  |
        | kubernetes.node_name                 | <main_node_name>                       |
        | kubernetes.pod_name                  | owlsm-stress-mkdir                |
        | kubernetes.pod_namespace             | owlsm-stress           |
        | kubernetes.pod_uid                   | <mkdir_uid>                 |
        | kubernetes.pod_labels.app            | owlsm-stress-mkdir           |
        | kubernetes.pod_labels."owlsm-automation" | pod |
        | kubernetes.container_id              | <mkdir_container_id>        |
    And I find the event in output in "30" seconds:
        | type                                 | CHMOD                                  |
        | action                               | ALLOW_EVENT                            |
        | process.cmd                          | /bin/chmod 777 /tmp/owlsm-stress-chmod |
        | data.target.file.path                | /tmp/owlsm-stress-chmod                |
        | data.target.file.filename            | owlsm-stress-chmod                     |
        | data.target.file.type                | REGULAR_FILE                           |
        | data.chmod.requested_mode            | 511                                    |
        | kubernetes.host_event                | False                                  |
        | kubernetes.node_name                 | <main_node_name>                       |
        | kubernetes.pod_name                  | owlsm-stress-chmod                |
        | kubernetes.pod_namespace             | owlsm-stress           |
        | kubernetes.pod_uid                   | <chmod_uid>                 |
        | kubernetes.pod_labels.app            | owlsm-stress-chmod           |
        | kubernetes.pod_labels."owlsm-automation" | pod |
        | kubernetes.container_id              | <chmod_container_id>        |
    And I find the event in output in "30" seconds:
        | type                                 | EXEC                             |
        | action                               | ALLOW_EVENT                      |
        | data.target.process.cmd              | /bin/sleep 86400                 |
        | kubernetes.host_event                | False                            |
        | kubernetes.node_name                 | <main_node_name>                 |
        | kubernetes.pod_name                  | owlsm-stress-exec           |
        | kubernetes.pod_namespace             | owlsm-stress      |
        | kubernetes.pod_uid                   | <exec_uid>            |
        | kubernetes.pod_labels.app            | owlsm-stress-exec      |
        | kubernetes.pod_labels."owlsm-automation" | pod |
        | kubernetes.container_id              | <exec_container_id>   |
    And I find the event in output in "30" seconds:
        | type                                 | FORK                                                     |
        | action                               | ALLOW_EVENT                                              |
        | process.cmd                          | /bin/sh -c /bin/true && exec /bin/sleep infinity        |
        | kubernetes.host_event                | False                                                    |
        | kubernetes.node_name                 | <main_node_name>                                         |
        | kubernetes.pod_name                  | owlsm-stress-fork                                   |
        | kubernetes.pod_namespace             | owlsm-stress                              |
        | kubernetes.pod_uid                   | <fork_uid>                                    |
        | kubernetes.pod_labels.app            | owlsm-stress-fork                              |
        | kubernetes.pod_labels."owlsm-automation" | pod |
        | kubernetes.container_id              | <fork_container_id>                           |
    When I delete the manifest "six_stress_pods.yaml"
    Then I find the event in output in "30" seconds:
        | type                                 | EXIT                                 |
        | action                               | ALLOW_EVENT                          |
        | process.cmd                          | /bin/sleep infinity                  |
        | data.exit_code                       | 0                                    |
        | data.signal                          | 9                                    |
        | kubernetes.host_event                | False                                |
        | kubernetes.node_name                 | <main_node_name>                     |
        | kubernetes.pod_name                  | owlsm-stress-write              |
        | kubernetes.pod_namespace             | owlsm-stress         |
        | kubernetes.pod_uid                   | <write_uid>               |
        | kubernetes.pod_labels.app            | owlsm-stress-write         |
        | kubernetes.pod_labels."owlsm-automation" | pod |
        | kubernetes.container_id              | <write_container_id>      |
    And I find the event in output in "30" seconds:
        | type                                 | EXIT                                 |
        | action                               | ALLOW_EVENT                          |
        | process.cmd                          | /bin/sleep infinity                  |
        | data.exit_code                       | 0                                    |
        | data.signal                          | 9                                    |
        | kubernetes.host_event                | False                                |
        | kubernetes.node_name                 | <main_node_name>                     |
        | kubernetes.pod_name                  | owlsm-stress-create             |
        | kubernetes.pod_namespace             | owlsm-stress        |
        | kubernetes.pod_uid                   | <create_uid>              |
        | kubernetes.pod_labels.app            | owlsm-stress-create        |
        | kubernetes.container_id              | <create_container_id>     |
        | kubernetes.pod_labels."owlsm-automation" | pod |
    And I find the event in output in "30" seconds:
        | type                                 | EXIT                            |
        | action                               | ALLOW_EVENT                     |
        | process.cmd                          | /bin/sleep infinity             |
        | data.exit_code                       | 0                               |
        | data.signal                          | 9                               |
        | kubernetes.host_event                | False                           |
        | kubernetes.node_name                 | <main_node_name>                |
        | kubernetes.pod_name                  | owlsm-stress-mkdir         |
        | kubernetes.pod_namespace             | owlsm-stress    |
        | kubernetes.pod_uid                   | <mkdir_uid>          |
        | kubernetes.pod_labels.app            | owlsm-stress-mkdir    |
        | kubernetes.pod_labels."owlsm-automation" | pod |
        | kubernetes.container_id              | <mkdir_container_id> |
    And I find the event in output in "30" seconds:
        | type                                 | EXIT                            |
        | action                               | ALLOW_EVENT                     |
        | process.cmd                          | /bin/sleep infinity             |
        | data.exit_code                       | 0                               |
        | data.signal                          | 9                               |
        | kubernetes.host_event                | False                           |
        | kubernetes.node_name                 | <main_node_name>                |
        | kubernetes.pod_name                  | owlsm-stress-chmod         |
        | kubernetes.pod_namespace             | owlsm-stress    |
        | kubernetes.pod_uid                   | <chmod_uid>          |
        | kubernetes.pod_labels.app            | owlsm-stress-chmod    |
        | kubernetes.pod_labels."owlsm-automation" | pod |
        | kubernetes.container_id              | <chmod_container_id> |
    And I find the event in output in "30" seconds:
        | type                                 | EXIT                           |
        | action                               | ALLOW_EVENT                    |
        | process.cmd                          | /bin/sleep 86400               |
        | data.exit_code                       | 0                              |
        | data.signal                          | 9                              |
        | kubernetes.host_event                | False                          |
        | kubernetes.node_name                 | <main_node_name>               |
        | kubernetes.pod_name                  | owlsm-stress-exec         |
        | kubernetes.pod_namespace             | owlsm-stress    |
        | kubernetes.pod_uid                   | <exec_uid>          |
        | kubernetes.pod_labels.app            | owlsm-stress-exec    |
        | kubernetes.pod_labels."owlsm-automation" | pod |
        | kubernetes.container_id              | <exec_container_id> |
    And I find the event in output in "30" seconds:
        | type                                 | EXIT                           |
        | action                               | ALLOW_EVENT                    |
        | process.cmd                          | /bin/sleep infinity            |
        | data.exit_code                       | 0                              |
        | data.signal                          | 9                              |
        | kubernetes.host_event                | False                          |
        | kubernetes.node_name                 | <main_node_name>               |
        | kubernetes.pod_name                  | owlsm-stress-fork         |
        | kubernetes.pod_namespace             | owlsm-stress    |
        | kubernetes.pod_uid                   | <fork_uid>          |
        | kubernetes.pod_labels.app            | owlsm-stress-fork    |
        | kubernetes.pod_labels."owlsm-automation" | pod |
        | kubernetes.container_id              | <fork_container_id> |
    And the owlsm log contains these messages this many times:
        | nri upsert skipped: invalid container id     | 0 |
        | container_id_to_pod_uid miss container_id=   | 0 |
        | pod_uid_to_k8s_info miss pod_uid=            | 0 |


Scenario: chmod on one hundred pods that existed before owlsm started
    Given owlsm is deployed cluster wide
    When I remove owlsm from the cluster
    And I deploy the manifest "hundred_preexisting_pods.yaml"
    And owlsm is deployed cluster wide
    And I chmod the file "/tmp/owlsm-preexisting" to "777" in every pod from "hundred_preexisting_pods.yaml"
    Then I find the event in output in "60" seconds:
        | type                      | CHMOD                         |
        | action                    | ALLOW_EVENT                   |
        | process.cmd               | chmod 777 /tmp/owlsm-preexisting |
        | data.target.file.path     | /tmp/owlsm-preexisting        |
        | data.target.file.filename | owlsm-preexisting             |
        | data.chmod.requested_mode | 511                           |
        | kubernetes.host_event     | False                         |
        | kubernetes.node_name      | <main_node_name>              |
        | kubernetes.pod_name       | <sample_name>                 |
        | kubernetes.pod_namespace  | owlsm-preexisting             |
        | kubernetes.pod_uid        | <sample_uid>                  |
        | kubernetes.pod_labels.app | owlsm-preexisting             |
        | kubernetes.container_id   | <sample_container_id>         |
    And the owlsm log contains these messages this many times:
        | nri upsert skipped: invalid container id   | 0 |
        | container_id_to_pod_uid miss container_id= | 0 |
        | pod_uid_to_k8s_info miss pod_uid=          | 0 |


Scenario: container restart keeps the pod uid and updates the container id
    Given owlsm is deployed cluster wide
    When I remove owlsm from the cluster
    And I deploy the manifest "container_restart_before.yaml"
    And owlsm is deployed cluster wide
    And I deploy the manifest "container_restart_after.yaml"
    And I chmod the file "/tmp/owlsm-restart-before-1" to "777" in pod "before"
    And I chmod the file "/tmp/owlsm-restart-after-1" to "777" in pod "after"
    Then I find the event in output in "30" seconds:
        | type                      | CHMOD                            |
        | action                    | ALLOW_EVENT                      |
        | process.cmd               | chmod 777 /tmp/owlsm-restart-before-1 |
        | data.target.file.path     | /tmp/owlsm-restart-before-1      |
        | data.target.file.filename | owlsm-restart-before-1           |
        | data.chmod.requested_mode | 511                              |
        | kubernetes.host_event     | False                            |
        | kubernetes.node_name      | <main_node_name>                 |
        | kubernetes.pod_name       | owlsm-restart-before             |
        | kubernetes.pod_namespace  | owlsm-restart                    |
        | kubernetes.pod_uid        | <before_uid>                     |
        | kubernetes.pod_labels.app | owlsm-restart-before             |
        | kubernetes.container_id   | <before_container_id>            |
    And I find the event in output in "30" seconds:
        | type                      | CHMOD                           |
        | action                    | ALLOW_EVENT                     |
        | process.cmd               | chmod 777 /tmp/owlsm-restart-after-1 |
        | data.target.file.path     | /tmp/owlsm-restart-after-1      |
        | data.target.file.filename | owlsm-restart-after-1           |
        | data.chmod.requested_mode | 511                             |
        | kubernetes.host_event     | False                           |
        | kubernetes.node_name      | <main_node_name>                |
        | kubernetes.pod_name       | owlsm-restart-after             |
        | kubernetes.pod_namespace  | owlsm-restart                   |
        | kubernetes.pod_uid        | <after_uid>                     |
        | kubernetes.pod_labels.app | owlsm-restart-after             |
        | kubernetes.container_id   | <after_container_id>            |
    When I restart pod "before" by killing its init pid and its uid stays the same while its container id changes
    And I restart pod "after" by killing its init pid and its uid stays the same while its container id changes
    And I chmod the file "/tmp/owlsm-restart-before-2" to "777" in pod "before"
    And I chmod the file "/tmp/owlsm-restart-after-2" to "777" in pod "after"
    Then I find the event in output in "30" seconds:
        | type                      | CHMOD                            |
        | action                    | ALLOW_EVENT                      |
        | process.cmd               | chmod 777 /tmp/owlsm-restart-before-2 |
        | data.target.file.path     | /tmp/owlsm-restart-before-2      |
        | data.target.file.filename | owlsm-restart-before-2           |
        | data.chmod.requested_mode | 511                              |
        | kubernetes.host_event     | False                            |
        | kubernetes.node_name      | <main_node_name>                 |
        | kubernetes.pod_name       | owlsm-restart-before             |
        | kubernetes.pod_namespace  | owlsm-restart                    |
        | kubernetes.pod_uid        | <before_uid>                     |
        | kubernetes.pod_labels.app | owlsm-restart-before             |
        | kubernetes.container_id   | <before_container_id>            |
    And I find the event in output in "30" seconds:
        | type                      | CHMOD                           |
        | action                    | ALLOW_EVENT                     |
        | process.cmd               | chmod 777 /tmp/owlsm-restart-after-2 |
        | data.target.file.path     | /tmp/owlsm-restart-after-2      |
        | data.target.file.filename | owlsm-restart-after-2           |
        | data.chmod.requested_mode | 511                             |
        | kubernetes.host_event     | False                           |
        | kubernetes.node_name      | <main_node_name>                |
        | kubernetes.pod_name       | owlsm-restart-after             |
        | kubernetes.pod_namespace  | owlsm-restart                   |
        | kubernetes.pod_uid        | <after_uid>                     |
        | kubernetes.pod_labels.app | owlsm-restart-after             |
        | kubernetes.container_id   | <after_container_id>            |
    And the owlsm log contains these messages this many times:
        | nri upsert skipped: invalid container id   | 0 |
        | container_id_to_pod_uid miss container_id= | 0 |
        | pod_uid_to_k8s_info miss pod_uid=          | 0 |
