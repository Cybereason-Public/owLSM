"""Build the test named on the command line and run it."""

from tests.flame_graph_idle import FlameGraphIdle
from tests.flame_graph_pressure_no_matches import FlameGraphPressureNoMatches
from tests.flame_graph_pressure_no_matches_flatbuffers import FlameGraphPressureNoMatchesFlatbuffers
from tests.flame_graph_pressure_yes_matches import FlameGraphPressureYesMatches
from tests.resource_graph import ResourceGraph
from tests.resource_graph_flatbuffers import ResourceGraphFlatbuffers
from tests.event_statistics import EventStatistics
from tests.event_statistics_flatbuffers import EventStatisticsFlatbuffers


class ProfilingTestFactory:
    @staticmethod
    def _classes():
        return [
            FlameGraphIdle,
            FlameGraphPressureNoMatches,
            FlameGraphPressureNoMatchesFlatbuffers,
            FlameGraphPressureYesMatches,
            ResourceGraph,
            ResourceGraphFlatbuffers,
            EventStatistics,
            EventStatisticsFlatbuffers,
        ]

    @classmethod
    def names(cls):
        return [test.name for test in cls._classes()]

    @classmethod
    def create(cls, test_name):
        for test in cls._classes():
            if test.name == test_name:
                return test()
        known = ", ".join(cls.names())
        raise RuntimeError(f"unknown test {test_name}. known tests: {known}")
