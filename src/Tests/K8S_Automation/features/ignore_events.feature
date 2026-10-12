Feature: ignore events

Scenario: owlsm ignores kube-system events by default
    Given owlsm is deployed cluster wide
    When I deploy the manifest "kube_system_pod.yaml"
    And I ensure the file "/tmp/owlsm-k8s-ignore-default-host-chmod" exists on main_node
    And I chmod the file "/tmp/owlsm-k8s-ignore-default-host-chmod" to "777" on main_node
    And I create and chmod the file "/tmp/owlsm-k8s-ignore-default-ks-chmod" to "777" in pod "kube_system"
    And I ensure the file "/tmp/owlsm-k8s-ignore-default-pod-chmod" exists in the test_pod
    And I chmod the file "/tmp/owlsm-k8s-ignore-default-pod-chmod" to "777" in the test_pod
    Then I find the event in output in "30" seconds:
        | type                      | CHMOD                                      |
        | action                    | ALLOW_EVENT                                |
        | process.file.filename     | chmod                                      |
        | process.cmd               | chmod 777 /tmp/owlsm-k8s-ignore-default-pod-chmod |
        | data.target.file.path     | /tmp/owlsm-k8s-ignore-default-pod-chmod    |
        | data.target.file.filename | owlsm-k8s-ignore-default-pod-chmod         |
        | data.chmod.requested_mode | 511                                        |
        | kubernetes.host_event     | False                                      |
        | kubernetes.node_name      | <main_node_name>                           |
        | kubernetes.pod_name       | <test_pod_name>                            |
        | kubernetes.pod_namespace  | <test_pod_namespace>                       |
        | kubernetes.pod_uid        | <test_pod_uid>                             |
        | kubernetes.pod_labels.app | <test_pod_label_app>                       |
        | kubernetes.container_id   | <test_pod_container_id>                    |
    And I find the event in output in "30" seconds:
        | type                      | CHMOD                                       |
        | action                    | ALLOW_EVENT                                 |
        | process.file.filename     | chmod                                       |
        | process.cmd               | chmod 777 /tmp/owlsm-k8s-ignore-default-host-chmod |
        | data.target.file.path     | /tmp/owlsm-k8s-ignore-default-host-chmod    |
        | data.target.file.filename | owlsm-k8s-ignore-default-host-chmod         |
        | data.chmod.requested_mode | 511                                         |
        | kubernetes.host_event     | True                                        |
        | kubernetes.node_name      | <main_node_name>                            |
        | kubernetes.pod_name       | None                                        |
        | kubernetes.pod_namespace  | None                                        |
        | kubernetes.pod_uid        | None                                        |
        | kubernetes.container_id   | None                                        |
    And I dont find the event in output in "10" seconds:
        | data.target.file.path | /tmp/owlsm-k8s-ignore-default-ks-chmod |
    And I dont find the event in output in "5" seconds:
        | kubernetes.pod_namespace | kube-system |


Scenario: owlsm always ignores owlsm pod events that are not part of the owlsm process tree
    Given I remove owlsm from the cluster
    When owlsm is deployed cluster wide
    And I change owlsm helm values:
        | config.kubernetes.ignore_host_events        | false |
        | config.kubernetes.ignore_kube_system_events | false |
    And I create and chmod the file "/tmp/owlsm-k8s-ignore-self-chmod" to "777" in the owlsm container
    And I ensure the file "/tmp/owlsm-k8s-ignore-self-chmod" has mode "777" in the owlsm container
    And I ensure the file "/tmp/owlsm-k8s-ignore-self-pod-chmod" exists in the test_pod
    And I chmod the file "/tmp/owlsm-k8s-ignore-self-pod-chmod" to "777" in the test_pod
    Then I find the event in output in "30" seconds:
        | type                      | CHMOD                                      |
        | action                    | ALLOW_EVENT                                |
        | process.file.filename     | chmod                                      |
        | process.cmd               | chmod 777 /tmp/owlsm-k8s-ignore-self-pod-chmod |
        | data.target.file.path     | /tmp/owlsm-k8s-ignore-self-pod-chmod       |
        | data.target.file.filename | owlsm-k8s-ignore-self-pod-chmod            |
        | data.chmod.requested_mode | 511                                        |
        | kubernetes.host_event     | False                                      |
        | kubernetes.node_name      | <main_node_name>                           |
        | kubernetes.pod_name       | <test_pod_name>                            |
        | kubernetes.pod_namespace  | <test_pod_namespace>                       |
        | kubernetes.pod_uid        | <test_pod_uid>                             |
        | kubernetes.pod_labels.app | <test_pod_label_app>                       |
        | kubernetes.container_id   | <test_pod_container_id>                    |
    And I dont find the event in output in "10" seconds:
        | data.target.file.path | /tmp/owlsm-k8s-ignore-self-chmod |
    And I dont find the event in output in "5" seconds:
        | kubernetes.pod_labels."app.kubernetes.io/name" | owlsm |
    And I change owlsm helm values:
        | config.kubernetes.ignore_host_events        | false |
        | config.kubernetes.ignore_kube_system_events | true |


Scenario: owlsm ignores host events
    Given I remove owlsm from the cluster
    When owlsm is deployed cluster wide
    And I change owlsm helm values:
        | config.kubernetes.ignore_host_events        | true  |
        | config.kubernetes.ignore_kube_system_events | false |
    And I deploy the manifest "kube_system_pod.yaml"
    And I ensure the file "/tmp/owlsm-k8s-ignore-host-chmod" exists on main_node
    And I chmod the file "/tmp/owlsm-k8s-ignore-host-chmod" to "777" on main_node
    And I create and chmod the file "/tmp/owlsm-k8s-ignore-host-ks-chmod" to "777" in pod "kube_system"
    And I ensure the file "/tmp/owlsm-k8s-ignore-host-pod-chmod" exists in the test_pod
    And I chmod the file "/tmp/owlsm-k8s-ignore-host-pod-chmod" to "777" in the test_pod
    Then I find the event in output in "30" seconds:
        | type                      | CHMOD                                      |
        | action                    | ALLOW_EVENT                                |
        | process.file.filename     | chmod                                      |
        | process.cmd               | chmod 777 /tmp/owlsm-k8s-ignore-host-ks-chmod |
        | data.target.file.path     | /tmp/owlsm-k8s-ignore-host-ks-chmod        |
        | data.target.file.filename | owlsm-k8s-ignore-host-ks-chmod             |
        | data.chmod.requested_mode | 511                                        |
        | kubernetes.host_event     | False                                      |
        | kubernetes.node_name      | <main_node_name>                           |
        | kubernetes.pod_name       | <kube_system_name>                         |
        | kubernetes.pod_namespace  | <kube_system_namespace>                    |
        | kubernetes.pod_uid        | <kube_system_uid>                          |
        | kubernetes.pod_labels.app | <kube_system_label_app>                    |
        | kubernetes.container_id   | <kube_system_container_id>                 |
    And I find the event in output in "30" seconds:
        | type                      | CHMOD                                      |
        | action                    | ALLOW_EVENT                                |
        | process.file.filename     | chmod                                      |
        | process.cmd               | chmod 777 /tmp/owlsm-k8s-ignore-host-pod-chmod |
        | data.target.file.path     | /tmp/owlsm-k8s-ignore-host-pod-chmod       |
        | data.target.file.filename | owlsm-k8s-ignore-host-pod-chmod            |
        | data.chmod.requested_mode | 511                                        |
        | kubernetes.host_event     | False                                      |
        | kubernetes.node_name      | <main_node_name>                           |
        | kubernetes.pod_name       | <test_pod_name>                            |
        | kubernetes.pod_namespace  | <test_pod_namespace>                       |
        | kubernetes.pod_uid        | <test_pod_uid>                             |
        | kubernetes.pod_labels.app | <test_pod_label_app>                       |
        | kubernetes.container_id   | <test_pod_container_id>                    |
    And I dont find the event in output in "10" seconds:
        | data.target.file.path | /tmp/owlsm-k8s-ignore-host-chmod |
    And I dont find the event in output in "5" seconds:
        | kubernetes.host_event | True |
    And I change owlsm helm values:
        | config.kubernetes.ignore_host_events        | false |
        | config.kubernetes.ignore_kube_system_events | true |


Scenario: owlsm ignores preexisting kube-system pods and host events
    Given I remove owlsm from the cluster
    And I deploy the test_pod
    And I deploy the manifest "kube_system_pod.yaml"
    When owlsm is deployed cluster wide
    And I change owlsm helm values:
        | config.kubernetes.ignore_host_events        | true |
        | config.kubernetes.ignore_kube_system_events | true |
    And I ensure the file "/tmp/owlsm-k8s-ignore-preexisting-host-chmod" exists on main_node
    And I chmod the file "/tmp/owlsm-k8s-ignore-preexisting-host-chmod" to "777" on main_node
    And I create and chmod the file "/tmp/owlsm-k8s-ignore-preexisting-ks-chmod" to "777" in pod "kube_system"
    And I ensure the file "/tmp/owlsm-k8s-ignore-preexisting-pod-chmod" exists in the test_pod
    And I chmod the file "/tmp/owlsm-k8s-ignore-preexisting-pod-chmod" to "777" in the test_pod
    Then I find the event in output in "30" seconds:
        | type                      | CHMOD                                      |
        | action                    | ALLOW_EVENT                                |
        | process.file.filename     | chmod                                      |
        | process.cmd               | chmod 777 /tmp/owlsm-k8s-ignore-preexisting-pod-chmod |
        | data.target.file.path     | /tmp/owlsm-k8s-ignore-preexisting-pod-chmod |
        | data.target.file.filename | owlsm-k8s-ignore-preexisting-pod-chmod     |
        | data.chmod.requested_mode | 511                                        |
        | kubernetes.host_event     | False                                      |
        | kubernetes.node_name      | <main_node_name>                           |
        | kubernetes.pod_name       | <test_pod_name>                            |
        | kubernetes.pod_namespace  | <test_pod_namespace>                       |
        | kubernetes.pod_uid        | <test_pod_uid>                             |
        | kubernetes.pod_labels.app | <test_pod_label_app>                       |
        | kubernetes.container_id   | <test_pod_container_id>                    |
    And I dont find the event in output in "10" seconds:
        | data.target.file.path | /tmp/owlsm-k8s-ignore-preexisting-ks-chmod |
    And I dont find the event in output in "5" seconds:
        | kubernetes.pod_namespace | kube-system |
    And I dont find the event in output in "10" seconds:
        | data.target.file.path | /tmp/owlsm-k8s-ignore-preexisting-host-chmod |
    And I dont find the event in output in "5" seconds:
        | kubernetes.host_event | True |
    And I change owlsm helm values:
        | config.kubernetes.ignore_host_events        | false |
        | config.kubernetes.ignore_kube_system_events | true |
