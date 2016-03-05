import requests

from .api import API


class DShieldAPI(API):
    """DShield API

    """

    _name = "DShield API"

    def dispatch(self, request):
        if 'port' in request:
            response=self.query_by_port(request['port'])
        elif 'ip' in request:
            response=self.query_by_ip(request['ip'])
        else:
            response = None

        return response

    def response(self, r):
        if self._require_raw:
            return r.text
        if r.status_code == 200:
            r = r.json()
            if 'ip' in r:
                resp = (
                    'Number: {}\nCount: {}\nAttacks: {}\nMaxdate: {}').format(
                        r['ip']['number'], r['ip']['count'],
                        r['ip']['attacks'], r['ip']['maxdate'],)
            else:
                resp = (
                    'Number: {}\nRecords: {}\nTargets: {}\nSources: {}\n'
                    'Date: {}\nTCP: {}\nUDP: {}'
                ).format(
                    r['number'], r['data']['records'], r['data']['targets'],
                    r['data']['sources'], r['data']['date'],r['data']['tcp'], r['data']['udp'],
                )
        else:
            resp=''
        return resp


    def query_by_ip(self, ip):
        request_url = 'http://isc.sans.edu/api/ip/{}?json'.format(ip)
        r = requests.get(request_url)
        return self.response(r)

    def query_by_port(self, port):
        request_url = 'http://isc.sans.edu/api/port/{}?json'.format(port)
        r = requests.get(request_url)
        return self.response(r)
