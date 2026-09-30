Feature: owlsm container events

Scenario: chmod in container that runs after owlsm is deployed
    Given owlsm is deployed cluster wide
    And I deploy the test_pod
    And I ensure the file "/tmp/owlsm-k8s-pod-after-chmod" exists in the test_pod
    When I chmod the file "/tmp/owlsm-k8s-pod-after-chmod" to "777" in the test_pod
    Then I find the event in output in "30" seconds:
        | type                      | CHMOD                                  |
        | action                    | ALLOW_EVENT                            |
        | process.cmd               | chmod 777 /tmp/owlsm-k8s-pod-after-chmod |
        | data.target.file.path     | /tmp/owlsm-k8s-pod-after-chmod         |
        | data.target.file.filename | owlsm-k8s-pod-after-chmod              |
        | data.chmod.requested_mode | 511                                    |
        | kubernetes.host_event     | False                                  |
        | kubernetes.node_name      | <main_node_name>                       |
        | kubernetes.pod_name       | <test_pod_name>                        |
        | kubernetes.pod_namespace  | <test_pod_namespace>                   |
        | kubernetes.pod_uid        | <test_pod_uid>                         |
        | kubernetes.pod_labels.app | <test_pod_label_app>                   |
        | kubernetes.container_id   | <test_pod_container_id>                |


Scenario: chmod in container that runs before owlsm is deployed
    Given I remove owlsm from the cluster
    And I deploy the test_pod
    And owlsm is deployed cluster wide
    And I ensure the file "/tmp/owlsm-k8s-pod-before-chmod" exists in the test_pod
    When I chmod the file "/tmp/owlsm-k8s-pod-before-chmod" to "777" in the test_pod
    Then I find the event in output in "30" seconds:
        | type                      | CHMOD                                   |
        | action                    | ALLOW_EVENT                             |
        | process.cmd               | chmod 777 /tmp/owlsm-k8s-pod-before-chmod |
        | data.target.file.path     | /tmp/owlsm-k8s-pod-before-chmod         |
        | data.target.file.filename | owlsm-k8s-pod-before-chmod              |
        | data.chmod.requested_mode | 511                                     |
        | kubernetes.host_event     | False                                   |
        | kubernetes.node_name      | <main_node_name>                        |
        | kubernetes.pod_name       | <test_pod_name>                         |
        | kubernetes.pod_namespace  | <test_pod_namespace>                    |
        | kubernetes.pod_uid        | <test_pod_uid>                          |
        | kubernetes.pod_labels.app | <test_pod_label_app>                    |
        | kubernetes.container_id   | <test_pod_container_id>                 |


Scenario: chmod event uses updated pod labels
    Given owlsm is deployed cluster wide
    And I deploy the test_pod
    And I ensure the file "/tmp/owlsm-k8s-pod-label-before" exists in the test_pod
    When I chmod the file "/tmp/owlsm-k8s-pod-label-before" to "777" in the test_pod
    Then I find the event in output in "30" seconds:
        | type                      | CHMOD                                    |
        | action                    | ALLOW_EVENT                              |
        | process.cmd               | chmod 777 /tmp/owlsm-k8s-pod-label-before |
        | data.target.file.path     | /tmp/owlsm-k8s-pod-label-before          |
        | data.target.file.filename | owlsm-k8s-pod-label-before               |
        | data.chmod.requested_mode | 511                                      |
        | kubernetes.host_event     | False                                    |
        | kubernetes.node_name      | <main_node_name>                         |
        | kubernetes.pod_name       | <test_pod_name>                          |
        | kubernetes.pod_namespace  | <test_pod_namespace>                     |
        | kubernetes.pod_uid        | <test_pod_uid>                           |
        | kubernetes.pod_labels.app | <test_pod_label_app>                     |
        | kubernetes.container_id   | <test_pod_container_id>                  |
    When I change the test_pod labels:
        | app      | test-pod-relabeled |
        | scenario | label-change       |
    And I sleep for "10" seconds
    And I ensure the file "/tmp/owlsm-k8s-pod-label-after" exists in the test_pod
    And I chmod the file "/tmp/owlsm-k8s-pod-label-after" to "777" in the test_pod
    Then I find the event in output in "30" seconds:
        | type                           | CHMOD                                   |
        | action                         | ALLOW_EVENT                             |
        | process.cmd                    | chmod 777 /tmp/owlsm-k8s-pod-label-after |
        | data.target.file.path          | /tmp/owlsm-k8s-pod-label-after          |
        | data.target.file.filename      | owlsm-k8s-pod-label-after               |
        | data.chmod.requested_mode      | 511                                     |
        | kubernetes.host_event          | False                                   |
        | kubernetes.node_name           | <main_node_name>                        |
        | kubernetes.pod_name            | <test_pod_name>                         |
        | kubernetes.pod_namespace       | <test_pod_namespace>                    |
        | kubernetes.pod_uid             | <test_pod_uid>                          |
        | kubernetes.pod_labels.app      | test-pod-relabeled                      |
        | kubernetes.pod_labels.scenario | label-change                            |
        | kubernetes.container_id        | <test_pod_container_id>                 |
    And I deploy the test_pod
