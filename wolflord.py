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
                 'statuses', 'refs', 'full_urls', '_backup_re']

    def __init__(self, formatspec=None):
        self.known_ips = GeoIPSet()
        self.log_data = []
        self.paths = {}
        self.refs = {}
        self.full_urls = {}
        self.statuses = {}
        self._backup_re = re.compile('ba(c)?k(up)?', re.I)

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
                self.add_line(line)

    def add_line(self, logline):
        # same process as the above really; probably should have an
        # internal method that does the data ETL and just call that
        # from both add_line and add_file...
        # parse the log file line based on self.fmt
        data = self.lp(logline)

        # split out some of the request data we may be
        # interested in.
        request_line = data['request_first_line'].split(' ')
        method = request_line[0]  # HTTP Method/Verb

        if method[0] == '"':
            method = method[1:]

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

        # man this would be so much nicer as a named tuple...
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
        """ A simple path-match check. Returns a list of al log entries
            where the URL path requested is *exactly* equal to a value.

            Arguments:
            path: the path to filter on (string)

        """

        if path not in self.paths:
            return []

        return [x for x in self.log_data if x[7] == path]

    def find_by_path_fuzzy(self, fuzzy_path):
        """ A simple 'contains' check for paths. less robust than
            find_by_path_prefix.

            Arguments:
            fuzzy_path: the string to filter ala contains check

        """
        return [x for x in self.log_data if fuzzy_path in x[7]]

    def _filter(self, item, prefix, contains=False):
        """ Helper function to filter path prefixes.

            Arguments:
            item: the item to be tested
            prefix: the (string | compiled regex) filter
        """
        if isinstance(prefix, re._pattern_type):
            return prefix.search(item)
        elif contains:
            return prefix in item
        else:
            return item.startswith(prefix)

    def find_by_path_prefix(self, pathprefix, exclude=None):
        """ Find log entries by path prefix, which may be a regex.

            Arguments:
            pathprefx: the test case to filter by (string | compiled regex)

            Keyword Arguments:
            exclude: the items to be excluded (None | string | compiled regex)

        """
        ret = [x for x in self.log_data if self._filter(x[7], pathprefix)]

        if exclude is not None:
            return filter(lambda x: self._filter(x[7], exclude), ret)

        return ret

    def find_by_referer(self, referer, not_flag=False):
        """ Find log entries with a specific referer.

            Arguments:
            referer: the (string | compiled regex) to check

            Keyword Arguments:
            not_flag: a Boolean to return those that do *not* match referer

        """

        if not_flag:
            return [x
                    for x in self.log_data
                    if not self._filter(x[1], referer, contains=True)]
        else:
            return [x
                    for x in self.log_data
                    if self._filter(x[1], referer, contains=True)]

    def find_by_statuscode(self, status, not_flag=False):
        """ Find log entries by HTTP status code.

            Arguments:
            status: the HTTP status code to filter by/for

            keyword arguments:
            not_flag: signal if we should check if the value is *not* equal
        """

        if not_flag:
            return [x for x in self.log_data if x[5] != status]
        else:
            return [x for x in self.log_data if x[5] == status]

    def find_by_method(self, method, not_flag=False):
        """ Find log entries by HTTP method.

            Arguments:
            method: the HTTP method verb to filter by/for

            keyword arguments:
            not_flag: signal if we should check if the value is *not* equal
        """

        if not_flag:
            return [x for x in self.log_data if x[6] != method]
        else:
            return [x for x in self.log_data if x[6] == method]

    def find_by_ip(self, ip):

        if ip not in self.known_ips:
            return []

        return [x for x in self.log_data if x[0] == ip]

    def find_by_country(self, country):
        # NOTE: this line is evil looking. Pure. Evil.
        ips = set([x
                   for x in self.known_ips.keys()
                   if self.known_ips[x]['country'] == country])
        return [x for x in self.log_data if x[0] in ips]

    def requests_with_urls(self):
        # returns a list of all requests that appear to have a
        # URL within them
        res = []
        for item in self.log_data:
            if '://' in item[7] or '://' in item[8]:
                res.append(item)
            elif ('%3A%2F%2F' in item[7].toupper()
                  or '%3A%2F%2F' in item[8].toupper()):
                res.append(item)
        return res

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

    def requests_with_commandi(self):
        # return all requests with command injection
        pass

    def request_with_backups(self):
        # return all requests that appear to be requesting
        # a backup file
        res = []
        for item in self.log_data:
            if self._backup_re.search(item[7]):
                res.append(item)
        return res

    def requests_with_repo(self):
        # return all requests that appear to be requesting
        # a repository file (aka .git)
        pass

    def requests_with_admin(self):
        # return all requests that appear to be requesting
        # something in the admin space, like wp-admin.
        # probably should have a filter for those requests
        # that are/are not successful.
        pass

    def requests_robot(self):
        # return all requests that have 'robot' in the UserAgent
        pass

    def requests_robotstxt(self):
        # return all requests that fetch the robots.txt file
        pass


if __name__ == "__main__":
    lord = WolfLord()

    import sys

    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            lord.add_file(arg)

        countries = sorted(lord.remotes_by_country().items(),
                           key=lambda x: len(x[1]), reverse=True)[0:11]
        print "# Top 10 Country Statistics:\n"
        for country in countries:
            print "- {0}: {1}".format(country[0], len(country[1]))

        print "\n# Host statistics: \n\nUnique hosts:", lord.unique_remotes()
        print "Total hosts:", lord.total_remotes()

        paths = sorted(lord.request_paths().items(),
                       key=lambda x: x[1], reverse=True)[0:11]
        bpaths = sorted(lord.request_paths().items(),
                        key=lambda x: x[1])[0:11]

        print "\n# Path Statistics:\n\nTop Paths:\n"

        for path in paths:
            print "-", path[0], path[1]

        print "\nLeast Frequent Paths:\n"

        for path in bpaths:
            print "-", path[0], path[1]
