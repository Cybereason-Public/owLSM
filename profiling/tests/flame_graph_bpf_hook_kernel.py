from ebpf_kernel_flame_graph import EbpfKernelFlameGraphTest
from globals import Strings, log


class FlameGraphBpfHookKernel(EbpfKernelFlameGraphTest):
    name = "FlameGraphBpfHookKernel"
    config_name = Strings.CONFIG_NO_RULE_MATCHES

    def run(self):
        log("run")
        self.profile_start()
        self.pressure()
        if self._owlsm.poll() is not None:
            raise RuntimeError(f"owLSM exited during the run with status {self._owlsm.returncode}")
        self.profile_stop()
