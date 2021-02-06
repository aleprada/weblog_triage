import pytest
import sys
import os
from weblog_triage.investigation import iocs
from weblog_triage.investigation import frequency
from weblog_triage.investigation import patterns
from weblog_triage.core import helper
from weblog_triage.core import alerts


def load_log():
    log_list = helper.parse_log(os.path.join(os.path.dirname(__file__)+"/data/log_test.log"))
    return log_list

def test_analyze_iocs():
    result_list = []
    log_requests = load_log()
    r1 = log_requests[0]
    a1 = alerts.Alert(alerts.AlertType.IOCs, alerts.AlertReason.IOC, r1.raw_request)
    result_list.append(a1)
    iocs_file = os.path.join(os.path.dirname(__file__))+"/data/iocs.txt"
    alerts_iocs = iocs.analyze_iocs(iocs_file, log_requests)
    assert alerts_iocs[0].request_str == a1.request_str


def test_analyse_frequency():
    log_requests = load_log()
    alerts_list_freq = frequency.analyze_by_freq(log_requests)
    assert len(alerts_list_freq) == 37


def test_analyze_patterns():
    log_requests = load_log()
    alerts_list_att_patterns = patterns.look_for_attack_patterns(log_requests)
    assert len(alerts_list_att_patterns) == 1
