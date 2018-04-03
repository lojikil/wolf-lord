# wolf-lord a simple tool for parsing &
# querying web logs. It's meant to do simple
# things like compare raw & unique clients,
# aggregate requests by country, search for
# anomalous traffic, &c.

from geoipset import GeoIPSet
import apache_log_parser
import re


class WolfLord(object):

    # log data is a linear list of all
    # events encountered in the logs
    __slots__ = ['known_ips', 'log_data', 'lp', 'fmt', 'paths',
                 'statuses', 'refs', 'full_urls']

    def __init__(self, formatspec=None):
        self.known_ips = GeoIPSet()
        self.log_data = []
        self.paths = {}
        self.refs = {}
        self.full_urls = {}
        self.statuses = {}

        if formatspec is None:
            self.fmt = '%h %l %u %t %r %s %b "%{Referer}i" "%{User-Agent}i"'
        else:
            self.fmt = formatspec

        self.lp = apache_log_parser.make_parser(self.fmt)

    def _add_path(self, path):
        if path in self.paths:
            self.paths[path] += 1
        else:
            self.paths[path] = 1

    def _add_ref(self, ref):
        if ref in self.refs:
            self.refs[ref] += 1
        else:
            self.refs[ref] = 1

    def _add_full_url(self, full_url):
        if full_url in self.full_urls:
            self.full_urls[full_url] += 1
        else:
            self.full_urls[full_url] = 1

    def add_file(self, logfile):
        with file(logfile) as fh:
            for line in fh:
                # parse the log file line based on self.fmt
                data = self.lp(line)

                # split out some of the request data we may be
                # interested in.
                request_line = data['request_first_line'].split(' ')
                method = request_line[0]  # HTTP Method/Verb
                if len(request_line) > 1:
                    fullurl = request_line[1]  # URL including query string
                else:
                    fullurl = ""

                urlparts = fullurl.split('?', 1)  # and now parsed...
                path = urlparts[0]  # Path section of the URL
                # potential query string
                if len(urlparts) > 1:
                    query_string = urlparts[1]
                else:
                    query_string = ""

                # potential version specifier
                if len(request_line) > 2:
                    httpver = request_line[2]  # HTTP/x.y specifier
                else:
                    httpver = "HTTP/unknown"

                # add the remote IP to the set of known hosts
                self.known_ips.add(data['remote_host'])

                # and add the path to our set of known paths
                self._add_path(path)

                # and add the referer to the list of known refs
                self._add_ref(data['request_header_referer'])

                # and finally add the full URL to the known list
                self._add_full_url(fullurl)

                res = [data['remote_host'],
                       data['request_header_referer'],
                       data['request_first_line'],
                       data['time_received_tz_isoformat'],
                       data['response_bytes_clf'],
                       data['status'],
                       method,
                       path,
                       query_string,
                       httpver,
                       data['request_header_user_agent']]
                self.log_data.append(res)

    def add_line(self, logline):
        # same process as the above really; probably should have an
        # internal method that does the data ETL and just call that
        # from both add_line and add_file...
        pass

    def remotes_by_country(self):
        return self.known_ips.ips_by_country()

    def unique_remotes(self):
        return len(self.known_ips)

    def total_remotes(self):
        return self.known_ips.total_ips()

    def referers(self):
        return self.refs

    def request_paths(self):
        return self.paths

    def request_urls(self):
        return self.full_urls

    def referers_with_count(self):
        return self.referers.items()

    def paths_with_count(self):
        return self.paths.items()

    # Honestly, reading all of these `find_by...` methods
    # makes me think that what I really want is some sort
    # of Datalog-like filtering langauge, or Sieve, or 
    # something...

    def find_by_path(self, path):

        if path not in self.paths:
            return []

        return [x for x in self.log_data if x[7] == path]

    def find_by_path_fuzzy(self, fuzzy_path):
        if path not in self.paths:
            return []

        return [x for x in self.log_data if fuzzy_path in x[7]]

    def find_by_path_prefix(self, pathprefix, exclude=None, is_regex=False):
        if path not in self.paths:
            return []

        return [x for x in self.log_data if x[7].startswith(pathprefix)]

    def find_by_statuscode(self, status, not_flag=False):
        """ Find log entries by HTTP status code.

            Arguments:
            status: the HTTP status code to filter by/for

            keyword arguments:
            not_flag: signal if we should check if the value is *not* equal
        """
        pass

    def find_by_ip(self, ip):

        if ip not in self.known_ips:
            return []

        return [x for x in self.log_data if x[0] == ip]

    def find_by_country(self, country):
        # NOTE: this line is evil looking. Pure. Evil.
        ips = set([x for x in self.known_ips.keys() if self.known_ips[x]['country'] == country])
        return [x for x in self.log_data if x[0] in ips]

    def requests_with_urls(self):
        # returns a list of all requests that appear to have a
        # URL within them
        pass

    def requests_with_sqli(self):
        # returns a list of all requests that appear to have SQLi
        # within the query parameters.
        # probably need to do something similar for all available
        # log data
        pass

    def requests_with_xss(self):
        # same as above, but for XSS
        pass

    def requests_with_cross_path(self):
        # return all requests for which the method is a POST,
        # but the referer is set. I need to check if this is
        # actually viable, since the Origin may not actually
        # be logged like that.
        pass


if __name__ == "__main__":
    lord = WolfLord()

    import sys

    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            lord.add_file(arg)

        countries = sorted(lord.remotes_by_country().items(),
                           key=lambda x: len(x[1]), reverse=True)[0:11]
        print "Top 10 Country Statistics:"
        for country in countries:
            print "{0}: {1}".format(country[0], len(country[1]))

        print "\nUnique hosts:", lord.unique_remotes()
        print "Total hosts:", lord.total_remotes()

        paths = sorted(lord.request_paths().items(),
                       key=lambda x: x[1], reverse=True)[0:11]

        print "\nTop path requests:"

        for path in paths:
            print path[0], path[1]
