from tests.flame_graph_idle import FlameGraphIdle
from tests.flame_graph_pressure_no_matches import FlameGraphPressureNoMatches
from tests.flame_graph_pressure_yes_matches import FlameGraphPressureYesMatches
from tests.resources_graph_run import ResourcesGraphRun


TESTS = [
    FlameGraphIdle(),
    FlameGraphPressureNoMatches(),
    FlameGraphPressureYesMatches(),
    ResourcesGraphRun(),
]
