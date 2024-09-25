import functools
from collections import defaultdict, namedtuple
from enum import Enum

import dns
import dns.asyncquery
import dns.update


class DNSRecordType(str, Enum):
    a = "A"
    aaaa = "AAAA"
    cname = "CNAME"
    mx = "MX"
    ns = "NS"
    txt = "TXT"
    soa = "SOA"
    ptr = "PTR"

class DNSManager:

    client: [functools.partial]
    DNS_SERVER: str = "5.35.9.32"
    DOMAIN: str = "example.com."
    ZONE: str = "example.com"

    def __init__(self) -> None:
        self.client = functools.partial(dns.asyncquery.tcp, where=self.DNS_SERVER)

    async def create_record(self, hostname, ip, record_type, ttl):

        action = dns.update.Update(self.ZONE)
        action.add(hostname, ttl, record_type, ip)
        await self.client(action)

    async def get_all_records(self):
        zone = dns.zone.from_xfr(dns.query.xfr(self.DNS_SERVER, self.DOMAIN))

        result = {}
        records = defaultdict(list)
        for name, ttl, rdata in zone.iterate_rdatas():
            if rdata.rdtype.name in result.keys():
                result[rdata.rdtype.name].append({
                    "hostname": name.to_text() + f".{self.ZONE}",
                    "ip": rdata.to_text(),
                    "ttl": ttl,
                })
            else:
                if rdata.rdtype.name == "SOA":
                    continue
                else:
                    result[rdata.rdtype.name] = [{
                        "hostname": name.to_text() + f".{self.ZONE}",
                        "ip": rdata.to_text(),
                        "ttl": ttl,
                    }]
        response = []
        for record_type in result.keys():
            response.append({
                "record_type": record_type,
                "records": result[record_type]
            })
        return response

    async def update_record(self, hostname, ip, record_type, ttl):
        action = dns.update.Update(self.ZONE)
        action.replace(hostname, ttl, record_type, ip)
        await self.client(action)

    async def delete_record(self, hostname, ip, record_type):
        action = dns.update.Update(self.ZONE)
        action.delete(hostname, record_type, ip)
        await self.client(action)
