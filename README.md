# Overview

wolf-lord is a simple web log processing & search framework. It is meant to make viewing & querying data stored 
within web logs more easily accessed. It includes `geoipset`, which is a simple counting set that can process
IP addresses by GeoIP info. It is ISC licensed, see `LICENSE` for details.

# Example Usage

In its most simple form, wolf-lord can be simply called from the command line to receive a set of statistics 
about the log file under analysis:

	$ python wolflord.py data/tufts_116.log 
	Top 10 Country Statistics:
	US: 34
	CN: 26
	RU: 9
	GB: 4
	No Country Data: 3
	NL: 2
	PL: 2
	FR: 1
	PT: 1
	CL: 1
	MO: 1

	Unique hosts: 90
	Total hosts: 540

	Top path requests:
	/ 270
	/phpmyadmin/scripts/setup.php 24
	/favicon.ico 16
	check.proxyradar.com:80 16
	 13
	/.git/HEAD 12
	/robots.txt 11
	/phpMyAdmin/scripts/setup.php 6
	/HNAP1 6
	51.140.55.230:9001 5
	/sdk 5

This displays:

- the top 10 countries within the dataset
- the Total number of unique hosts as well as the total number of hosts
- the top requested paths by count

Of course, that's not necessarily useful or incredibly novel (not that there really _is_ such as thing
as novelty in our world as a global maxima), save for as a quick glance at the data. Where wolf-lord is
meant to truly shine is as part of an analyst's REPL:

- ETL web log data into a lojikil format for processing
- Helper methods (such as `find_by_ip` or `find_by_statuscode`) to uncover interesting patterns within the logs
- Automatic GeoIP inclusion of client IPs

Additionally, wolf-lord includes `geoipset`, which is a counting set data structure that utilizes MaxMind's
GeoIP lite database to retrieve time zone and lat/long for a set of IPs. Additionally, since it is a 
counting set, it will store the number of occurrences for an IP address within a given data set. By default,
it can be called from the command line to return a TSV file thusly: 

	$ python geoipset.py data/random_ips.txt 
	23.40.169.46	1	NL	52.374,4.8897	Europe/Amsterdam
	100.57.153.36	1	US	38.0,-97.0	None
	107.143.228.37	3	US	33.9137,-98.4934	America/Chicago
	122.132.199.231	5	JP	35.69,139.69	Asia/Tokyo
	48.175.85.192	1	US	40.7357,-74.1724	America/New_York
	44.82.87.2	2	US	32.8072,-117.1649	America/Los_Angeles
	36.17.0.250	1	CN	26.9689,109.7725	Asia/Shanghai
	164.241.164.196	1	US	38.0,-97.0	None
	115.185.64.61	1	IN	33.7333,75.15	Asia/Kolkata
	230.9.224.250	1	No Country Data	0, 0	No TZ Data
	134.189.141.219	1	US	32.7792,-97.5195	America/Chicago
	222.3.253.161	1	JP	35.69,139.69	Asia/Tokyo
	39.206.122.209	1	ID	-6.175,106.8286	None
	58.199.221.162	1	CN	24.4798,118.0819	Asia/Shanghai
	184.252.230.131	1	US	38.0,-97.0	None

# To Do

- return entries by most/least common referer/client-IP/path
- finish the URL/XSS/SQLi/whatever stubs
- referer intelligence (IP lookup, GeoIP, &c.)
