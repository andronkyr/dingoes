import dns.resolver
from netaddr import *

class DnsResolver(object):
    def __init__(self, dns_resolvers = ['8.8.8.8', '8.8.4.4'], retry_servfail=False, single_resolver=False):
        self.dns_query_timeout = 20
        self.dns_resolvers = dns_resolvers
        self.my_resolver = False
        self.retry_servfail = retry_servfail
        self.single_resolver = single_resolver
        self.main()

    def main(self):
        self.my_resolver = dns.resolver.Resolver()
        self.my_resolver.timeout = self.dns_query_timeout
        self.my_resolver.lifetime = self.dns_query_timeout
        self.my_resolver.retry_servfail = self.retry_servfail
        if self.single_resolver:
            self.my_resolver.nameservers = self.dns_resolvers[:1]
        else:
            self.my_resolver.nameservers = self.dns_resolvers

    def get_ip_address(self, domain):
        """Resolve domain name into IP address

        Return IPSet() and manage common DNS lookup error scenarios
        """
        result = IPSet()
        try:
            query_responses = self.my_resolver.query(domain, 'A')
            for query_response in query_responses:
                ip_address = query_response.to_text()
                result.add(ip_address)
        except dns.resolver.NXDOMAIN:
            result.add('255.255.255.255/32') # Represent NXDOMAIN
        except dns.resolver.NoAnswer:
            raise Exception("DNS Response Empty")
        except dns.exception.Timeout:
            raise Exception("DNS Lookup Timeout")
        except dns.resolver.NoNameservers:
            raise Exception("DNS Lookup Error")
        except:
            raise Exception("DNS Lookup Error")
        return result
