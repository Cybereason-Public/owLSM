class GlobalObjects:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GlobalObjects, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.CLUSTER = None
        self.PYTEST_SESSION_PID = None
        self._initialized = True


global_objects = GlobalObjects()
