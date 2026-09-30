Feature: owlsm lifecycle

Scenario: deploy_and_remove_owlsm_twice
    Given owlsm is deployed cluster wide
    When I remove owlsm from the cluster
    When owlsm is deployed cluster wide
    When I remove owlsm from the cluster
    When owlsm is deployed cluster wide
