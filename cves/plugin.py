from urllib import urlopen

import json

CVEJSON = 'https://www.cvedetails.com/json-feed.php?vendor_id=0&product_id=0&version_id=0&orderby=1&cvssscoremin=8&numrows=3'


class CvePlugin(object):
    def get_cves(self, cardinal, user, channel, msg):
        try:
            url = CVEJSON
            f = urlopen(url).read()
            data = json.loads(f)
            cardinal.sendMsg(channel, " -- 3 latests critical CVE's with exploits available -- ")
            cardinal.sendMsg(channel, "-----------------------------------------------")
#CVE #1
            cve_id = data[0]['cve_id']
            cvss_score = data[0]['cvss_score']
            publish_date = data[0]['publish_date']
            update_date = data[0]['update_date']
            summary = data[0]['summary']
            response = '%s - Score: %s - Published: %s - Updated: %s  - Description:\n%s\n' % (cve_id, cvss_score, publish_date, update_date, summary)
            cardinal.sendMsg(channel, response.encode('utf-8'))
#CVE #2
            cve_id = data[1]['cve_id']
            cvss_score = data[1]['cvss_score']
            publish_date = data[1]['publish_date']
            update_date = data[1]['update_date']
            summary = data[1]['summary']
            response = '%s - Score: %s - Published: %s - Updated: %s  - Description:\n%s\n' % (cve_id, cvss_score, publish_date, update_date, summary)
            cardinal.sendMsg(channel, response.encode('utf-8'))
#CVE #3
            cve_id = data[2]['cve_id']
            cvss_score = data[2]['cvss_score']
            publish_date = data[2]['publish_date']
            update_date = data[2]['update_date']
            summary = data[2]['summary']
            response = '%s - Score: %s - Published: %s - Updated: %s  - Description:\n%s\n' % (cve_id, cvss_score, publish_date, update_date, summary)
            cardinal.sendMsg(channel, response.encode('utf-8'))
        except Exception:
            cardinal.sendMsg(channel, "Could not retrieve latest cves")

    get_cves.commands = ['cves']
    get_cves.help = ['Returns latest cves',
                   'Syntax: .cves']


def setup():
    return CvePlugin()
