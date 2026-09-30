#include "global_objects.hpp"

namespace owlsm::globals 
{
    config::Config g_config {};
    ProbeManager g_probe_manager {};
    ShellsDB g_shells_db {};
    kubernetes::KubernetesClient g_kubernetes_client {};
}