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
import threading
import queue
import time
import sys
import json



output_queue = queue.Queue()
mutex = threading.Lock()

class myThread (threading.Thread):
   def __init__(self, threadID, name, queue, nr_domains, report):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.name = name
      self.queue = queue
      self.report = report
      self.nr_domains = nr_domains

   def run(self):
      while True:
        # Pop a query from the queue

        data = self.queue.get()
        # print("ThreadID {} processing domain {}".format(self.threadID,data))
        output_queue.put(self.report.generate_results(data))
        # Informational Printing 
        #mutex.acquire()
        #try:
        p = 100 - self.queue.qsize()/self.nr_domains*100
        sys.stdout.write('\r[{}] {}% - Queries Left: {}'.format (('#' * int(p / 2)).ljust(50, ' '), int(p),self.queue.qsize()))
        sys.stdout.flush()
        #finally:
        #    mutex.release()

        self.queue.task_done()
        time.sleep(.2)


def workload(report,threat_count,queue):
    domains = queue.qsize()
    thread_number = threat_count
    threadlist = []
    threads=[]
    for i in range(0,int(thread_number)):
        threadlist.append("Thread-"+str(i))
    threadID = 1
    for tName in threadlist:
       thread = myThread(threadID, tName, queue, domains, report)
       thread.setDaemon(True)
       threads.append(thread)
       threadID += 1
    
    for t in threads:
       t.start()
    queue.join()


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
        # Answer is NXDomain. Let's investigate if it is due to blocking or the domain does not actually exist.
        if IPAddress('255.255.255.255') in ip_addresses and IPAddress('255.255.255.255') in blockpages:
            try:
                # Get the IP address from Google DNS
                google_dns_response = self.resolver.get_ip_address(phishing_domain)
                nx_intersection = ip_addresses & google_dns_response
                # If Google DNS and the DNS server responds with different results, the
                # blocking was successful. 
                if len(nx_intersection) == 0:
                    response = 'NXDOMAIN'
                    #return response
                    return True
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
            return True
            # return intersection
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
        blocked = self.is_blocked(ip_addresses, blockpages, phishing_domain)

        if blocked:
            result = 'SITE_BLOCKED_OK' +"(" + ",".join(str(answer).replace("255.255.255.255","NXDOMAIN")  for answer in ip_addresses) +")"

        #    self.add_to_stats(resolver_name)
        # If the website is not blocked, return with the website's IP address
        else:
            results = []
            for ip_address in ip_addresses:
                results.append(str(ip_address).replace("255.255.255.255","NXDOMAIN") )
            result = ",".join(results)
        return result

    def open_csv_file(self):
        '''Open CSV file and add header'''
        if not os.path.exists('output'):
            os.makedirs('output')
        try:
            self.output_file_handler = open("output/" + self.output_file +".csv", 'w')
        except Exception as e:
            print("\n\nError opening output file {}: {}\n".format(args.o, e))
            exit(1)

        csv_header_fieldnames = ["Domain"]
        csv_header_fieldnames.extend(sorted(self.resolver_names))
        csv_writer = csv.DictWriter(self.output_file_handler, delimiter=',', fieldnames=csv_header_fieldnames)
        csv_writer.writeheader()
        return csv_writer

    def generate_results(self,domain):
        result = {}
        result['Domain'] = domain
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
        return (result)


    def write_results(self,thread_count,domain_queue):
        '''Write results into CSV file'''
        counter = 1
        workload(self,thread_count,domain_queue)

        # Write CSV header
        csv_writer = self.open_csv_file()

        with open(("output/" + self.output_file+".json"), 'w') as f:
            while not (output_queue.empty()):
                row = output_queue.get()
                csv_writer.writerow(row)
                f.write(json.dumps(str(row))+"\n")
                for resolver in row:
                    if ("SITE_BLOCKED_OK" in str(row[resolver])):
                        self.add_to_stats(resolver)
                    # Flush file after writing each line
                self.output_file_handler.flush()
        # Close output file
        self.output_file_handler.close()


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
