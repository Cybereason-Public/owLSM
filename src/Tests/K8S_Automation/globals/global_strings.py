from pathlib import Path
from datetime import datetime
import os


class GlobalStrings:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GlobalStrings, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.AUTOMATION_ROOT_DIR = Path(__file__).resolve().parent.parent
        self.REPO_ROOT = self.AUTOMATION_ROOT_DIR.parent.parent.parent
        self.LOG_PATH = self.AUTOMATION_ROOT_DIR / "automation.log"
        self.OWLSM_OUTPUT_LOG = self.AUTOMATION_ROOT_DIR / "owLSM_output.log"
        self.OWLSM_LOGGER_LOG = self.AUTOMATION_ROOT_DIR / "owlsm.log"
        kubeconfig_env = os.environ.get("KUBECONFIG")
        self.KUBECONF_PATH = Path(kubeconfig_env) if kubeconfig_env else Path.home() / ".kube" / "config"
        self.LOG_STORAGE_PATH = "/tmp/k8s_automation_logs/"
        self.TESTS_START_TIME = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")
        self.SSH_USER = "root"
        self.SSH_PASSWORD = "Password1"
        self.SSH_KEY_PATH = os.environ.get("OWLSM_OKE_SSH_KEY", "")
        self.KIND = "kind"
        self.OCI = "oci"
        self.KIND_CLUSTER_NAME = os.environ.get("OWLSM_KIND_CLUSTER_NAME", self.KIND)
        self.CLUSTER_TYPE = os.environ.get("OWLSM_CLUSTER_TYPE", self.KIND)
        if self.CLUSTER_TYPE == self.KIND:
            self.KUBE_CONTEXT = f"{self.KIND}-{self.KIND_CLUSTER_NAME}"
        else:
            self.KUBE_CONTEXT = os.environ.get("OWLSM_KUBE_CONTEXT", "")
        self.REPO_K8S_DIR = self.REPO_ROOT / "kubernetes"
        self.HELM_CHART_PATH = self.REPO_K8S_DIR / "chart"
        self.OWLSM_HELM_RELEASE = "owlsm"
        self.OWLSM_NAMESPACE = "kube-system"
        self.OWLSM_DAEMONSET = "owlsm"
        self.OWLSM_APP_NAME = "owlsm"
        self.OWLSM_IMAGE_REPOSITORY = os.environ.get("OWLSM_IMAGE_REPOSITORY", "owlsm")
        self.OWLSM_IMAGE_TAG = os.environ.get("OWLSM_IMAGE_TAG", "local")
        self.MANIFESTS_DIR = self.AUTOMATION_ROOT_DIR / "resources" / "manifests"
        self.TEST_POD_ALIAS = "test_pod"
        self.TEST_POD_NAME = "test-pod"
        self.TEST_POD_NAMESPACE = "owlsm-test-pod"
        self.TEST_POD_IMAGE = "busybox:1.36"
        self.OWLSM_CONTAINER_NAME = "owlsm"
        self.OWLSM_CONTAINER_LOG_PATH = "/var/log/owlsm/owlsm.log"
        self._initialized = True


global_strings = GlobalStrings()
