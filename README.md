# pysmtp
Dependencies
```bash
pip3 install requests dnspython colored
```

Usage
```bash
python3 pysmtp.py --lookup-domain mail.polimi.it --greeting-domain polimi.it --no-ip-scan --uses-helo --no-dig
```

Help
```
usage: pysmtp.py [-h] --lookup-domain LOOKUP_DOMAIN --greeting-domain GREETING_DOMAIN [--linefeed LINEFEED] [--smtp-port PORT] [--no-ip-scan] [--no-dig] [--uses-helo | --uses-elho]

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
  --no-dig              omits digging all target domain records
  --uses-helo
  --uses-elho
```