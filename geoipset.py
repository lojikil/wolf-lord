# A rich set-like data structure that
# stores GeoIP data about an IP address
# Basically, this implements a counting
# set, but also stores additional
# information as retrieved from the 
# MaxMind GeoIP database 
# probably useful outside of wolf-lord,
# but for now only exists within this 
# project.

from geoip import geolite2

class GeoIPSet(object):

    __slots__ = ['ips']

    def __init__(self):
        self.ips = {}

    def add(self, key):

        if key in self.ips:
            self.ips[key]["count"] += 1
        else:
            tmp = {}
            data = geolite2.lookup(key)
            tmp['count'] = 1

            if data is not None:
                tmp['country'] = data.country
                tmp['timezone'] = data.timezone
                if data.location is not None:
                    tmp['location'] = ','.join([str(x) for x in data.location])
                else:
                    tmp['location'] = '0, 0'

            self.ips[key] = tmp

    def __setitem__(self, key, count):
        if key in self.ips:
            self.ips[key]['count'] = count

    def __getitem__(self, key):
        return self.ips.get(key)

    def __len__(self):
        # this returns *UNIQUE* IP addresses
        # added to the set. use "total_ips"
        # if you need total number of times
        # the IP was seen in a given log
        return len(self.ips.keys())

    def ips_by_timezone(self):
        res = {}

        for ip in self.ips.keys():
            tz = self.ips[ip].get('timezone', 'No TZ Data')

            if tz not in res:
                res[tz] = [ip]
            else:
                res[tz].append(ip)

        return res

    def ips_by_country(self):
        res = {}

        for ip in self.ips.keys():
            country = self.ips[ip].get('country', 'No Country Data')

            if country not in res:
                res[country] = [ip]
            else:
                res[country].append(ip)

        return res

    def total_ips(self):
        res = 0

        for ip in self.ips.keys():
            res += self.ips[ip]['count']

        return res
