import os


class GlobalNumbers:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GlobalNumbers, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.MIN_NUMBER_OF_NODES_IN_TEST_CLUSTER = 2
        cluster_type = os.environ.get("OWLSM_CLUSTER_TYPE", "kind")
        default_rollout = "180" if cluster_type == "oci" else "120"
        default_pod_ready = "90" if cluster_type == "oci" else "30"
        self.OWLSM_ROLLOUT_TIMEOUT_SECONDS = int(
            os.environ.get("OWLSM_ROLLOUT_TIMEOUT_SECONDS", default_rollout)
        )
        self.TEST_POD_READY_TIMEOUT_SECONDS = int(
            os.environ.get("OWLSM_TEST_POD_READY_TIMEOUT_SECONDS", default_pod_ready)
        )
        self.TEST_NAMESPACE_DELETE_TIMEOUT_SECONDS = 60
        self._initialized = True


global_numbers = GlobalNumbers()
