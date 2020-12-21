#class Request -> IP , domain name, referer_url, HTTP status, HTTP METHOD, User Agent, SIZE RESquest?, timestamp
class LogRequest:
    
    def __init__(self,ip,url,referer_url,http_status,http_method,user_agent, size_request, timestamp, raw_request):
        self.ip = ip
        self.url = url
        self.referer_url = referer_url
        self.http_status = http_status
        self.http_method = http_method
        self.user_agent = user_agent
        self.size_request = size_request
        self.timestamp = timestamp
        self.raw_request = raw_request
        self.bad_method = None

    def add_bad_method(self,bad_method):
        self.bad_method = bad_method
    