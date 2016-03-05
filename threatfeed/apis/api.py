import abc

import requests


class API(abc.ABC):
    """Base API Class

    @attributes:
    _name: API name.
    _require_raw: if it is requested to return raw response from remote resources
    """

    _name = None

    @abc.abstractmethod
    def dispatch(self, request):
        """ Dispatch request to diffrent query method

        @params:
        request: a dict indicates the query type and this content

        @return:
        string: if response is successfully retrieved from remote resources
        '': No record is found in remote resources
        None: Doesn't support this query method
        """
        pass

    @abc.abstractmethod
    def response(self, r):
        """ return readable response tring

        """
        pass

    @classmethod
    def get_name(cls):
        return cls._name

    @classmethod
    def query(cls, request, raw):
        self = cls()
        self._require_raw = raw

        resp = self.dispatch(request)
        if resp is None:
            return "{} doesn't support this query type\n".format(self.get_name())
        elif not resp:
            return "No record is found in {}\n".format(self.get_name())
        else:
            return "{}\nSource: {}\n".format(resp, self.get_name())
