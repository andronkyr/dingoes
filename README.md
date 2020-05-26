# DiNgoeS

Compare website blocking effectiveness of popular public DNS servers

This tool downloads the latest feed of malicious and deceptive websites
from ~~hpHost~~ different threat intelligence providers  and looks up whether these websites are
blocked on popular third-party malware-blocking and anti-phishing DNS
services.

Read the full blog article and see the initial report on the [CryptoAUSTRALIA Blog](https://blog.cryptoaustralia.org.au/2017/12/23/best-threat-blocking-dns-providers/)

## DNS Services Supported

  * [Comodo Secure DNS](https://www.comodo.com/secure-dns/)
  * [Comodo Shield](https://shield.dome.comodo.com/)
  * [IBM Quad 9](https://www.quad9.net/)
  * [Norton ConnectSafe](https://connectsafe.norton.com/configureRouter.html)
  * [Neustar Free Recursive DNS](https://www.neustar.biz/security/dns-services/free-recursive-dns-service)
  * [OpenDNS Home](https://www.opendns.com/)
  * [SafeDNS](https://www.safedns.com/)
  * [Strongarm](https://strongarm.io/)
  * [Yandex.DNS](https://dns.yandex.com/advanced/)
  * [CIRA](https://www.cira.ca/cybersecurity-services/canadian-shield)
  * More services can be added at the respective `services.ini` file

## ~~hpHosts Feeds Supported~~ (Deprecated)

  * **PSH** : Sites engaged in Phishing (default)
  * **EMD** : Sites engaged in malware distribution
  * **EXP** : Sites engaged in hosting, development or distribution of exploits

## Threat Intelligence Feeds

The threat intelligence feeds that are used as an input can be configured in the `feeds.ini` file. Currently the feeds supported are `urlhaus`, `sans` and `bambenek`

## Install
  * Require python3
  * Install requirements with `pip`:

      `$ pip install -r requirements.txt`

## Usage

  * Run DiNgoeS with the following command:

      `$ python dingoes.py`

> The CSV format report will be available in the `output` directory. Open in Excel
> or similar for further processing. 
> Additionally the report is generated in JSON format for easier processing. 

* Build and run via `docker-compose`

  `$ docker-compose up -d`

## Switches

  * ~~`-o` : CSV report file name.~~ The report name is the name of the input file concatenated with the date of the test
  * `-u`: Download and update threat intelligence feed (default: y). **For large feeds the process might take a while**
  * `-n` : Number of websites from the threat intelligence feed feed to test (default: 500)
  * `-s` : Shell type - if spinner exceptions occur, set to 1 (default: 0)
  * `-t`: Number of threads that are performing the DNS resolution.

## Support

Contact us on Twitter at [@CryptoAUSTRALIA](https://twitter.com/CryptoAustralia)
