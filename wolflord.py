# wolf-lord a simple tool for parsing &
# querying web logs. It's meant to do simple
# things like compare raw & unique clients,
# aggregate requests by country, search for 
# anomalous traffic, &c.

from geoipset import GeoIPSet
import apache_log_parser


class WolfLord(object):

    # log data is a linear list of all
    # events encountered in the logs
    # __slots__ = ['known_ips', 'log_data', 'lp', 'fmt', 'paths',
    #             'statuses']

    def __init__(self, formatspec=None):
        self.known_ips = GeoIPSet()
        self.log_data = []
        self.paths = {}
        self.statues = {}

        if formatspec is None:
            self.fmt = '%h %l %u %t %r %s %b "%{Referer}i" "%{User-Agent}i"'
        else:
            self.fmt = formatspec

        self.lp = apache_log_parser.make_parser(self.fmt)

    def add_file(self, logfile):
        with file(logfile) as fh:
            for line in fh:
                # parse the log file line based on self.fmt
                data = self.lp(line)

                # split out some of the request data we may be 
                # interested in.
                request_line = data['request_first_line'].split(' ')
                method = request_line[0] # HTTP Method/Verb
                fullurl = request_line[1] # URL including query string
                urlparts = fullurl.split('?', 1) # and now parsed...
                path = urlparts[0] # Path section of the URL
                # potential query string
                if len(urlparts) > 1:
                    query_string = urlparts[1]
                else:
                    query_string = ""
                httpver = request_line[2] # HTTP/x.y specifier

                # add the remote IP to the set of known hosts
                self.known_ips.add(data['remote_host'])

                res = [data['remote_host'],
                       data['request_header_referer'],
                       data['request_first_line'],
                       data['time_received_tz_isoformat'],
                       data['response_bytes_clf'],
                       data['status'],
                       method,
                       path,
                       query_string,
                       httpver]
                self.log_data.append(res)

    def add_line(self, logline):
        # same process as the above really; probably should have an
        # internal method that does the data ETL and just call that
        # from both add_line and add_file...
        pass

    def remotes_by_country(self):
        return self.known_ips.ips_by_country()

    def referers(self):
        return self.referers.keys()

    def paths(self):
        return self.paths.keys()

    def referers_with_count(self):
        return self.referers.items()

    def paths_with_count(self):
        return self.paths.items()

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

        countries = lord.remotes_by_country()

        print "Country Statistics:"
        for country in countries.keys():
            print "{0}: {1}".format(country, len(countries[country]))
