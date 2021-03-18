from time import sleep

import dns.resolver
import smtplib
import socket
import argparse

from printer import *
from requests import get
import os
import editor

# Arguments
parser = argparse.ArgumentParser(description='Python SMTP utility')
parser.add_argument('--lookup-domain', dest='lookup_domain', help='smtp lookup server', required=True)
parser.add_argument('--greeting-domain', dest='greeting_domain', help='helo/elho domain', required=True)
parser.add_argument('--linefeed', type=str, default="\r\n", dest='linefeed', help='SMTP encoding linefeed')
parser.add_argument('--smtp-port', type=int, default=25, dest='port', help='SMTP port')
parser.add_argument('--no-ip-scan', action='store_true', dest='noip', help='omits ip checks')
group = parser.add_mutually_exclusive_group()
group.add_argument('--uses-helo', action='store_true')
group.add_argument('--uses-elho', action='store_false')

args = parser.parse_args()
lookup_domain = args.lookup_domain
greeting_domain = args.greeting_domain
port = args.port
linefeed = args.linefeed
uses_helo = args.uses_helo
uses_elho = args.uses_elho


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
    answers = dns.resolver.Resolver().query(lookup_domain, 'MX')

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
    print("\nReading machine IP status")

    dprint(f"Current hostname: {current_hostname()}")
    dprint(f"Current private ip: {current_local_ip()}")
    dprint(f"Current public ip: {current_public_ip()}")

try:
    print("\nConnecting with SMTP server")
    server = smtplib.SMTP(mx_record, port, local_hostname=current_hostname())

    cprint(f"Connected to SMTP server {lookup_domain} ({mx_record}) over port {port}")

    while True:
        tokens = input(">> ").split(" ")
        cmd = tokens[0]

        if not cmd.strip():
            continue

        try:
            if cmd == "quit":
                print("Bye")
                server.quit()
                exit(0)
            elif cmd == "mail":
                if uses_elho:
                    dprint("Helo-ing server")
                    helo_response = server.helo(greeting_domain)
                    cprint(helo_response)
                else:
                    dprint("Ehlo-ing server")
                    elho_response = server.ehlo(greeting_domain)
                    cprint(elho_response)


                from_code = 0
                while from_code not in range(200, 399):
                    mail_from = input("MAIL FROM: ")
                    from_response = server.mail(mail_from)
                    from_code = int(from_response[0])

                    if from_code in range(200, 399):
                        cprint(from_response)
                    else:
                        eprint(from_response)

                rcpt_code = 0
                while rcpt_code not in range(200, 399):
                    rcpt_to = input("RCPT TO: ")
                    rcpt_response = server.rcpt(rcpt_to)
                    rcpt_code = int(rcpt_response[0])

                    if rcpt_code in range(200, 399):
                        cprint(rcpt_response)
                    else:
                        eprint(rcpt_response)

                message = editor.edit(contents=b"").decode("utf-8")

                if len(message.strip()) == 0:
                    wprint("Message is empty")

                dprint("Sending data to server")
                data_response = server.data(message)
                cprint(data_response)
                cprint("Sent")
            elif cmd == "console":
                # PyCharm console
                mail_from = input("MAIL FROM: ")
                rcpt_to = input("RCPT TO: ")
                assert len(mail_from) > 0 and len(rcpt_to) > 0

                print(f"Interactive mode enabled. Type . to send message.")

                message = ""
                last_line = ""
                while True:
                    last_line = input("")

                    if last_line != ".":
                        message += last_line + linefeed
                        continue
                    else:
                        break

                dprint("Sending")
                server.sendmail(mail_from, rcpt_to, message)
            else:
                wprint("Command not recognized")

        except:
            eprint("Unknown error occourred")


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
