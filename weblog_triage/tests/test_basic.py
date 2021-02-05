import unittest
from weblog_triage.investigation.iocs import analyze_iocs, look_for_ioc_in_misp
from weblog_triage.investigation.frequency import analyze_by_freq
from weblog_triage.investigation.patterns import look_for_attack_patterns

from weblog_triage.core.helper import parse_log, LogRequest
from weblog_triage.core.alerts import Alert, AlertReason, AlertType


class TestAnalysisClass(unittest.TestCase):
    def get_requests(self):
        requests =parse_log("log_test.log")
        return requests

    def test_analyze_iocs(self):
        result_list = []
        log_requests = self.get_requests()
        r1 = log_requests[0]
        a1 = Alert(AlertType.IOCs, AlertReason.IOC, r1.raw_request)
        result_list.append(a1)
        alerts_iocs = analyze_iocs("iocs.txt", log_requests)
        self.assertEqual(alerts_iocs[0].request_str, a1.request_str)

    def test_analyse_frequency(self):
        log_requests = self.get_requests()
        alerts_list_freq = analyze_by_freq(log_requests)
        self.assertEqual(len(alerts_list_freq), 37)

    def test_analyze_patterns(self):
        log_requests = self.get_requests()
        alerts_list_att_patterns = look_for_attack_patterns(log_requests)
        self.assertEqual(len(alerts_list_att_patterns), 1)


if __name__ == '__main__':
    unittest.main()
