from enum import Enum


class AlertReason(Enum):
    PUT = "A request using a PUT HTTP method was found."
    DELETE = "A request using a DELETE HTTP method was found."
    UNCOMMON = "A request using an UNCOMMON HTTP method was found."
    FREQ_IP = "This IP is a low frequency request."
    USER_AGENT = "This User Agent might be suspicious and it has low freq pattern."
    BYTE_SIZE = "This Bite Size request might be suspicious and it has low freq pattern."
    SUCCESSFUL = "This request was successful."
    IOC = "This request contains the IOC that you are looking for."
    MISP = "This request contains an IOC stored at your MISP instance"
    SQLI= "This request contains a possible SQL injection attack"
    XSS= "This request contains a possible XSS attack"
    BACKDOOR= "This request contains a connection to a possible backdoor"
    CMD_INJ= "This request contains a Command Injection Attack"
    MISCONF= "This request shows a possible misconfiguration"
    ADMINSITE= "This request is targeting an admin site"
    PATH_TRAV= "This request might contain a Path Traversal vulnerability"
    ENCODING= "This request might contain encoded characters"
    BASE64= "This request might contain base64 characters"
    LONG_URL= "This request seem too long and it might be suspicious"


class AlertType(Enum):
    FREQUENCY = "This investigation approach is focused on triaging low frequency requests that might be suspicious"
    IOCs = "This investigation approach is focused on triaging requests that contain a match with an Indicator of Compromise (IoC)"
    Pattern = "This investigation approach is focused on looking for popular attack patterns such as XSS, SQLi, etc"


#add number of times is repeated.
class Alert():
    def __init__(self, type, reason, request_str):
        self.type = type
        self.reason = reason
        self.request_str = request_str
        self.more_info = ""
        self.misp_event_id = 0
        self.ioc_detected= ""

    def add_more_info(self, more_info):
        self.more_info = more_info

    def add_misp_event_id(self, misp_event_id):
        self.misp_event_id = misp_event_id

    def add_ioc_detected(self, ioc):
        self.ioc_detected = ioc



