import csv
import re
import os
from etaprogress.progress import ProgressBar
from dateutil.parser import parse
from netaddr import *
from dingoes.resolver import DnsResolver
from ascii_graph import Pyasciigraph
from ascii_graph.colors import *
from ascii_graph.colordata import vcolor

class Report(object):
    '''Report class'''
    def __init__(self, domains, output_file, config):
        self.domains = domains
        self.output_file = output_file
        self.output_file_handler = False
        self.config = config
        self.resolver = DnsResolver(retry_servfail=True)
        self.csv_writer = False
        self.resolvers = config.confvalues
        self.resolver_names = config.confvalues.keys()
        self.statistics = {}
        # Initialise stats dict
        for item in self.resolver_names:
            self.statistics[item] = 0

    def is_blocked(self, ip_addresses, blockpages, phishing_domain):
        '''Verifies whether the IP address is on the blocked page list'''
        # TODO: blockpages should be generated from self.config
        intersection = ip_addresses & blockpages
        # If response was NXDOMAIN, we need to verify if a non-filtering server respond with NXDOMAIN too
        # e.g. the domain is taken down
        if IPAddress('255.255.255.255') in ip_addresses:
            try:
                # Get the IP address from Google DNS
                google_dns_response = self.resolver.get_ip_address(phishing_domain)
                nx_intersection = ip_addresses & google_dns_response
                # If Google DNS and the DNS server responds with different results, the
                # blocking was unsuccessful
                if len(nx_intersection) == 0:
                    response = 'NXDOMAIN'
                    return response
                # If Google DNS and the DNS server under inspection responds with the same IP addresses
                # the block is unsuccessful
                else:
                    return False
            # If response is NXDOMAIN from Google DNS, or any other error, return False
            # which means we could not determine whether the site was blocked or not
            except:
                return False
        elif len(intersection) > 0:
            # If the IP address is in the list of IP addresses of block pages
            # the website is blocked successfully
            return intersection
        # Return 'non-blocked' in case of any other errors
        else:
            return False

    def generate_result(self, ip_addresses, blockpages, resolver_name, phishing_domain):
        """
        Generates cell content in the CSV file
        """
        result = False
        # Return 'SITE_BLOCKED_OK' if the phishing site's domain name resolves to
        # one of the block pages of the DNS services.
        if self.is_blocked(ip_addresses, blockpages, phishing_domain):
            result = 'SITE_BLOCKED_OK'
            self.add_to_stats(resolver_name)
        # If the website is not blocked, return with the website's IP address
        else:
            results = []
            for ip_address in ip_addresses:
                results.append(str(ip_address))
            result = "\n".join(results)
        return result

    def open_csv_file(self):
        '''Open CSV file and add header'''
        if not os.path.exists('output'):
            os.makedirs('output')
        try:
            self.output_file_handler = open("output/" + self.output_file, 'w')
        except Exception as e:
            print("\n\nError opening output file {}: {}\n".format(args.o, e))
            exit(1)
        # csv_header_fieldnames = [
        #     'Added to hpHosts',
        #     'Phishing Site Domain',
        #     'Phishing Site IP Address'
        # ]
        csv_header_fieldnames = ["Domain"]
        csv_header_fieldnames.extend(sorted(self.resolver_names))
        csv_writer = csv.DictWriter(self.output_file_handler, delimiter=',', fieldnames=csv_header_fieldnames)
        csv_writer.writeheader()
        return csv_writer

    def write_results(self, entries_to_process):
        '''Write results into CSV file'''
        counter = 1
        # Create progress bar
        bar = ProgressBar(entries_to_process, max_width=72)
        # Write CSV header
        csv_writer = self.open_csv_file()
        # Iter through each feed entry from the feed
        for feed_entry in self.domains:
            # Stop processing if the number of entries are higher than in '-n'
            if counter > entries_to_process:
                break
            result = {}
            # Update progress bar
            bar.numerator = counter
            print(bar, end='\r')
            # Write phishing site details into CSV
            result['Domain'] = feed_entry
            #result['Added to hpHosts'] = parse(feed_entry.published)
            #result['Phishing Site IP Address'] = re.findall(r'[0-9]+(?:\.[0-9]+){3}', feed_entry.summary)[0]
            # Iterate through the third-party DNS services
            for resolver_name in self.resolver_names:
                try:
                    dns_resolvers = self.resolvers[resolver_name]['resolvers']
                    domain = result['Domain']
                    resolver = DnsResolver(dns_resolvers, single_resolver=True)
                    # Retrieve the IP addresses that the third-party DNS service resolves
                    ip_addresses = resolver.get_ip_address(domain)
                except Exception as e:
                    # Write DNS lookup error message in the CSV file
                    result[resolver_name] = e
                else:
                    blockpages = self.resolvers[resolver_name]['blockpages']
                    result[resolver_name] = self.generate_result(ip_addresses, blockpages, resolver_name, domain)
            # Write results into file
            csv_writer.writerow(result)
            # Flush file after writing each line
            self.output_file_handler.flush()
            counter += 1
        # Close output file
        self.output_file_handler.close()
        return counter

    def add_to_stats(self, resolver_name):
        self.statistics[resolver_name] += 1

    def print_stats_diagram(self, total_entries):
        data = []
        graph = Pyasciigraph(separator_length=4)
        for resolver_name in sorted(self.resolver_names):
            item = (resolver_name, self.statistics[resolver_name])
            data.append(item)
        item = ('TOTAL', total_entries)
        data.append(item)
        for line in graph.graph('Blocking Statistics:', data):
            print(line)
