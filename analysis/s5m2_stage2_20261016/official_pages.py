"""Optional official HTML provenance capture; offline verification is the default.
Only public Panasonic web pages; no device addresses or camera requests.
"""
import argparse
import datetime
import html.parser
import urllib.request
import urllib.parse
from common import WORK, RESULTS, save, load, digest

PAGES = {
    'oss_ver1': 'https://ospo.panasonic.com/oss/dsc/DC-S5M2.html',
    'oss_ver2': 'https://ospo.panasonic.com/oss/dsc/DC-S5M2%28Ver2%29.html',
    'firmware_release': 'https://av.jpn.support.panasonic.com/support/dsc/download/ff/dl/s5m2.html',
    'firmware_download': 'https://av.jpn.support.panasonic.com/support/dsc/download/ff/dl/s5m2_dl.html',
}

class Links(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links=[]
    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key in ('href','src') and value:
                self.links.append(value)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fetch', action='store_true')
    args=parser.parse_args()
    directory=WORK/'official_pages'
    if args.fetch:
        directory.mkdir(parents=True, exist_ok=False)
        records=[]
        for label,url in PAGES.items():
            with urllib.request.urlopen(url, timeout=40) as response:
                final=response.url
                assert urllib.parse.urlsplit(final).hostname in ('ospo.panasonic.com','av.jpn.support.panasonic.com')
                data=response.read()
                headers={k: response.headers[k] for k in ('Content-Type','Content-Length','Last-Modified','ETag') if k in response.headers}
                status=response.status
            (directory/(label+'.html')).write_bytes(data)
            links=Links();links.feed(data.decode('utf-8',errors='replace'))
            relevant=[urllib.parse.urljoin(final,x) for x in links.links if any(s in x.lower() for s in
                         ('source/dsc','s5m2','zip/'))]
            records.append({'label':label,'requested_url':url,'final_url':final,'status':status,
                            'retrieved_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            'size':len(data),'sha256':digest(data),'headers':headers,
                            'relevant_links':sorted(set(relevant))})
        save(directory/'capture.json',records)
    records=load(directory/'capture.json')
    for r in records:
        data=(directory/(r['label']+'.html')).read_bytes()
        assert len(data)==r['size'] and digest(data)==r['sha256']
    save(RESULTS/'official_pages.json',{'pages':records,
         'boundary':'Official page/link provenance and local hashes only; not vendor signature or deployed build attestation.'})
    print('PASS: 4 official page snapshots and current links; original content remains local')

if __name__=='__main__':
    main()
