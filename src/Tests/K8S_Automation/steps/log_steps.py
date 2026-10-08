import time

from pytest_bdd import given, then, when

from Utils.log_utils import count_owlsm_log_messages
from Utils.logger_utils import logger


@given("the owlsm log contains these messages this many times:")
@when("the owlsm log contains these messages this many times:")
@then("the owlsm log contains these messages this many times:")
def the_owlsm_log_contains_these_messages_this_many_times(datatable):
    expected = [(row[0].strip(), int(row[1].strip())) for row in datatable]
    if not expected:
        raise RuntimeError("owlsm log table is empty")
    counts = count_owlsm_log_messages([needle for needle, _count in expected])
    mismatches = []
    for needle, expected_count in expected:
        actual, samples = counts[needle]
        logger.log_info(
            f"owlsm log message {needle!r} count={actual} expected={expected_count}"
        )
        if actual != expected_count:
            sample_text = "; ".join(samples) if samples else "no matching line"
            mismatches.append(
                f"{needle!r} expected {expected_count} got {actual}. samples: {sample_text}"
            )
    assert not mismatches, "owlsm log counts mismatch:\n" + "\n".join(mismatches)
