from enum import Enum


class AlertReason(Enum):
    PUT = "A request using a PUT HTTP method was found"
    DELETE = "A request using a DELETE HTTP method was found"
    UNCOMMON = "A request using an UNCOMMON HTTP method was found"
    FREQ_IP = "This IP is a low frequency request"
    USER_AGENT = "This User Agent might be suspicious and it has low freq pattern."
    BYTE_SIZE = "This Bite Size request might be suspicious and it has low freq pattern"
    SUCCESSFUL = "This request was successful"


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

    def add_more_info(self, more_info):
        self.more_info = more_info

