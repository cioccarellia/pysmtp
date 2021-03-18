import dns.resolver
import smtplib
import socket
import argparse

import os
from printer import *
from requests import get

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Arguments
parser = argparse.ArgumentParser(description='Python SMTP wrapper')
parser.add_argument('--lookup-domain', dest='lookup_domain', help='smtp lookup server')
parser.add_argument('--helo-domain', dest='helo_domain', help='helo domain')
parser.add_argument('--linefeed', type=str, default="\r\n", dest='linefeed', help='helo domain')
parser.add_argument('--smtp-port', type=int, default=25, dest='port', help='smtp port')
parser.add_argument('--no-ip-scan', action='store_true', dest='noip', help='omits ip checks')

args = parser.parse_args()
lookup_domain = args.lookup_domain
helo_domain = args.helo_domain
port = args.port
linefeed = args.linefeed


# Returns current machine network hostname
def current_hostname():
    return socket.gethostname()


# Returns current IPV4 private address
def current_local_ip():
    return socket.gethostbyname(current_hostname())


# Returns external ip address
def current_public_ip():
    return get('https://api.ipify.org').text


def fetch_dns_mx_entry():
    """
    Queries and returns the MX record for the matching domain.
    """
    dprint("Querying ", lookup_domain, " MX record")
    answers = dns.resolver.query(lookup_domain, 'MX')

    if len(answers) == 1:
        rdata = answers[0]
        cprint(f"Selected MX entry to [{rdata.exchange}].")

        return str(rdata.exchange)
    else:
        wprint("Multiple MX records were found. Selecting the first one.")
        return str(answers[0].exchange)


def dig_all_records():
    os.system(f"dig -t ANY {lookup_domain} +answer")


print(f"Digging public records for {lookup_domain}")
dig_all_records()
print(f"Fetching MX DNS entries for {lookup_domain}")
mx_record = fetch_dns_mx_entry()

# Output
if not args.noip:
    print("Reading machine IP status")

    dprint(f"Current hostname: {current_hostname()}")
    dprint(f"Current private ip: {current_local_ip()}")
    dprint(f"Current public ip: {current_public_ip()}")

try:
    print("Connecting with SMTP server")
    server = smtplib.SMTP(mx_record, port)

    cprint(f"Connected to SMTP server {lookup_domain} ({mx_record}) over port ")

    while True:
        tokens = input(">> ").split(" ")
        cmd = tokens[0]

        try:
            if cmd == "help":
                print("quit, file, interactive")
            elif cmd == "quit":
                server.quit()
                exit(0)
            elif cmd == "file":
                filename = str(tokens[1])
                mail_from = str(tokens[2])
                rcpt_to = str(tokens[3])
                iterations = int(tokens[2])

                assert len(filename) > 0 and len(mail_from) > 0 and len(rcpt_to) > 0

                print(f"Reading file {filename} and composing SMTP message")
                file = open(filename, "r")
                content = file.read().split("\n")

                message = ""
                for line in content:
                    if line.startswith("#"):
                        continue
                    message += line + linefeed

                file.close()

                for i in range(0, iterations):
                    server.sendmail(mail_from, rcpt_to, message)

            elif cmd == "interactive":
                mail_from = str(tokens[1])
                rcpt_to = str(tokens[2])
                assert len(mail_from) > 0 and len(rcpt_to) > 0

                print(f"Interactive mode enabled. Type . to compose and send.")

                message = ""
                last_line = ""
                while True:
                    last_line = input("")

                    if last_line != ".":
                        message += last_line + linefeed
                        continue
                    else:
                        break

                server.sendmail(mail_from, rcpt_to, message)
            else:
                wprint("Command not recognized")

        except Exception:
            eprint("Fuck you")


except smtplib.SMTPAuthenticationError:
    eprint(
        "SMTPAuthenticationError: SMTP authentication went wrong. Most probably the server didn’t accept the username/password combination provided.")
except smtplib.SMTPNotSupportedError:
    eprint("SMTPNotSupportedError: The command or option attempted is not supported by the server.")
except smtplib.SMTPHeloError:
    eprint("SMTPHeloError: The server fucking refused our HELO message.")
except smtplib.SMTPConnectError:
    eprint("SMTPConnectError: Error occurred during establishment of a connection with the server..")
except smtplib.SMTPDataError:
    eprint("SMTPDataError: The SMTP server refused to accept the message data.")
except smtplib.SMTPRecipientsRefused:
    eprint(
        "SMTPRecipientsRefused: All recipient addresses refused. The errors for each recipient are accessible through the attribute recipients, which is a dictionary of exactly the same sort as SMTP.sendmail() returns.")
except smtplib.SMTPSenderRefused:
    eprint(
        "SMTPSenderRefused: Sender address refused. In addition to the attributes set by on all SMTPResponseException exceptions, this sets ‘sender’ to the string that the SMTP server refused.")
except smtplib.SMTPResponseException:
    eprint(
        "SMTPResponseException: Base class for all exceptions that include an SMTP error code. These exceptions are generated in some instances when the SMTP server returns an error code. The error code is stored in the smtp_code attribute of the error, and the smtp_error attribute is set to the error message.")
except smtplib.SMTPServerDisconnected:
    eprint(
        "SMTPServerDisconnected: This exception is raised when the server unexpectedly disconnects, or when an attempt is made to use the SMTP instance before connecting it to a server.")
except smtplib.SMTPException:
    eprint(
        "SMTPResponseException: Subclass of OSError that is the base exception class for all the other exceptions provided by this module.")
