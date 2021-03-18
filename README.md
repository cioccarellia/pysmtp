# pysmtp
Dependencies
```bash
pip3 install requests dnspython colored
```

Usage
```bash
usage: pysmtp.py [-h] --lookup-domain LOOKUP_DOMAIN --greeting-domain GREETING_DOMAIN [--linefeed LINEFEED] [--smtp-port PORT] [--no-ip-scan] [--uses-helo | --uses-elho]

Python SMTP utility

optional arguments:
  -h, --help            show this help message and exit
  --lookup-domain LOOKUP_DOMAIN
                        smtp lookup server
  --greeting-domain GREETING_DOMAIN
                        helo/elho domain
  --linefeed LINEFEED   SMTP encoding linefeed
  --smtp-port PORT      SMTP port
  --no-ip-scan          omits ip checks
  --uses-helo
  --uses-elho
```