Feature: owlsm config

Scenario: chmod event stops after helm disables chmod
    Given owlsm is deployed cluster wide
    And I deploy the test_pod
    And I ensure the file "/tmp/owlsm-k8s-config-chmod-on" exists in the test_pod
    When I chmod the file "/tmp/owlsm-k8s-config-chmod-on" to "777" in the test_pod
    Then I find the event in output in "15" seconds:
        | type                      | CHMOD                                   |
        | action                    | ALLOW_EVENT                             |
        | process.cmd               | chmod 777 /tmp/owlsm-k8s-config-chmod-on |
        | data.target.file.path     | /tmp/owlsm-k8s-config-chmod-on          |
        | data.target.file.filename | owlsm-k8s-config-chmod-on               |
        | data.chmod.requested_mode | 511                                     |
        | kubernetes.host_event     | False                                   |
        | kubernetes.node_name      | <main_node_name>                        |
        | kubernetes.pod_name       | <test_pod_name>                         |
        | kubernetes.pod_namespace  | <test_pod_namespace>                    |
        | kubernetes.pod_uid        | <test_pod_uid>                          |
        | kubernetes.pod_labels.app | <test_pod_label_app>                    |
        | kubernetes.container_id   | <test_pod_container_id>                 |
    When I change owlsm helm values:
        | config.features.file_monitoring.events.chmod | false |
    And I ensure the file "/tmp/owlsm-k8s-config-chmod-off" exists in the test_pod
    And I chmod the file "/tmp/owlsm-k8s-config-chmod-off" to "666" in the test_pod
    Then I dont find the event in output in "15" seconds:
        | type                      | CHMOD                                    |
        | process.cmd               | chmod 666 /tmp/owlsm-k8s-config-chmod-off |
        | data.target.file.path     | /tmp/owlsm-k8s-config-chmod-off          |
        | data.target.file.filename | owlsm-k8s-config-chmod-off               |
        | data.chmod.requested_mode | 438                                      |
    And I change owlsm helm values:
        | config.features.file_monitoring.events.chmod | true |
