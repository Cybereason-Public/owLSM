Feature: owlsm host events

Scenario: host_chmod_event
    Given owlsm is deployed cluster wide
    And I ensure the file "/tmp/owlsm-k8s-host-chmod" exists on main_node
    When I chmod the file "/tmp/owlsm-k8s-host-chmod" to "777" on main_node
    Then I find the event in output in "30" seconds:
        | type                      | CHMOD                           |
        | action                    | ALLOW_EVENT                     |
        | process.file.filename     | chmod                           |
        | process.cmd               | chmod 777 /tmp/owlsm-k8s-host-chmod |
        | data.target.file.path     | /tmp/owlsm-k8s-host-chmod       |
        | data.target.file.filename | owlsm-k8s-host-chmod            |
        | data.chmod.requested_mode | 511                             |
        | kubernetes.host_event     | True                            |
        | kubernetes.node_name      | <main_node_name>                |
        | kubernetes.pod_name       | None                            |
        | kubernetes.pod_namespace  | None                            |
        | kubernetes.pod_uid        | None                            |
        | kubernetes.container_id   | None                            |
