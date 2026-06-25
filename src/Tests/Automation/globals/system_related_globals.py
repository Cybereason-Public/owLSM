from pathlib import Path
from datetime import datetime
import os
import shutil

class SystemGlobals:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SystemGlobals, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    class NetworkingGlobals:
        _instance = None
        
        def __new__(cls):
            if cls._instance is None:
                cls._instance = super(SystemGlobals.NetworkingGlobals, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance
        
        def __init__(self):
            if self._initialized:
                return
            
            self.SERVER_IP_ADDR = "10.99.99.99"
            self.SERVER_IPv6_ADDR = "fd8a:1c2b:3d4e:5f60::1"
            self.SERVER_IP = f"{self.SERVER_IP_ADDR}/24"
            self.SERVER_IPv6 = f"{self.SERVER_IPv6_ADDR}/64"
            self.CLIENT_IP_ADDR = "10.99.99.98"
            self.CLIENT_IPv6_ADDR = "fd8a:1c2b:3d4e:5f60::2"
            self.CLIENT_IP = f"{self.CLIENT_IP_ADDR}/24"
            self.CLIENT_IPv6 = f"{self.CLIENT_IPv6_ADDR}/64"
            self.NS_IP_ADDR = self.CLIENT_IP_ADDR
            self.NS_IP = self.CLIENT_IP
            self.NS_IPv6_ADDR = self.CLIENT_IPv6_ADDR
            self.NS_IPv6 = self.CLIENT_IPv6
            self.NS_NAME = "clientns"
            self.VETH_HOST = "veth_host"
            self.VETH_NS = "veth_ns"
            self.FILE_EXISTENCE_FLAG_FILE = "/tmp/file_existence_test_success.flag"
            self.CLIENT_MESSAGE = "Hello from netcat client!"
            self.SERVER_MESSAGE = "Hello from netcat server!"
            self.NETCAT_PATH = os.path.realpath(shutil.which("netcat"))
            self.server_object = None
            self.client_object = None
            self.error_messages = []
            self._initialized = True
    
    def __init__(self):
        if self._initialized:
            return
        
        self.AUTOMATION_ROOT_DIR = Path(__file__).resolve().parent.parent
        self.LOG_PATH = self.AUTOMATION_ROOT_DIR / "automation.log"
        self.OWLSM_PATH = self.AUTOMATION_ROOT_DIR / "owlsm" / "bin" / "owlsm"
        self.RESOURCES_PATH = self.AUTOMATION_ROOT_DIR / "resources"
        self.OWLSM_DB_PATH = self.AUTOMATION_ROOT_DIR / "owlsm" / "resources" / "owlsm.db"
        self.OWLSM_PROCESS_OBJECT = None
        self.PYTEST_SESSION_PID = None
        self.OWLSM_SETUP_TIME_IN_SECONDS = 60
        self.USER_NAME = "automation_test_user"
        self.PASSWORD = self.USER_NAME
        self.NO_SUDO_USER_NAME = f"{self.USER_NAME}_nosudo"
        self.NO_SUDO_PASSWORD = self.NO_SUDO_USER_NAME
        self.OWLSM_OUTPUT_LOG = self.AUTOMATION_ROOT_DIR / "owLSM_output.log"
        self.OWLSM_OUTPUT_LOG_FD = None
        self.OWLSM_LOGGER_LOG = self.AUTOMATION_ROOT_DIR / "owlsm" / "bin" / "owlsm.log"
        self.TESTS_START_TIME = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")
        self.LOG_STORAGE_PATH = "/tmp/automation_logs/"
        self.networking_globals = self.NetworkingGlobals()
        self._initialized = True

system_globals = SystemGlobals()

