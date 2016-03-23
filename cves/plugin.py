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

            for cve in data:
                cve_text = (
                    '%s - Score: %s - Published: %s - Updated: %s  - Description:\n%s\n'
                    % (cve['cve_id'], cve['cvss_score', cve['publish_date'], cve['update_date'], cve['summary']))

                cardinal.sendMsg(channel, cve_text.encode('utf-8'))

        except Exception:
            cardinal.sendMsg(channel, "Could not retrieve latest CVEs")

    get_cves.commands = ['cves']
    get_cves.help = ['Returns latest cves',
                   'Syntax: .cves']


def setup():
    return CvePlugin()
