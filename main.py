import dns.resolver
import smtplib, ssl
import socket

from printer import *
from config import *
from telnetlib import Telnet
from requests import get

from progressbar import progressbar

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def current_hostname():
    return socket.gethostname()


def current_local_ip():
    return socket.gethostbyname(current_hostname())


def current_public_ip():
    return get('https://api.ipify.org').text


def fetch_dns_mx_entry():
    dprint("Querying ", lookup_domain, " MX record")
    answers = dns.resolver.query(lookup_domain, 'MX')

    if len(answers) == 1:
        rdata = answers[0]
        oprint(f"Fixed MX entry to [{rdata.exchange}].")

        return str(rdata.exchange)
    else:
        wprint("Multiple MX records were found. Select one:")


# Output
print("Reading machine IP status")

dprint(f"Current hostname: {current_hostname()}")
dprint(f"Current private ip: {current_local_ip()}")
dprint(f"Current public ip: {current_public_ip()}")

print("fetching MX DNX entries")
record = fetch_dns_mx_entry()

try:
    print("Connecting with SMTP server")
    server = smtplib.SMTP(record, 25)

    task_count = len(tasks)

    if task_count == 0:
        wprint("No tasks found. Quitting")
        exit(0)
    else:
        print(f"Found {task_count} tasks to be executed.")

    for index, task in enumerate(tasks):
        print(f"Task #{index + 1}/{task_count}")

        if task["type"] == "single":
            mail_from = task["mail_from"]
            rcpt_to = task["rcpt_to"]
            message = task["data"]

            dprint(f"MAIL FROM: {mail_from}")
            dprint(f"RCPT TO: {rcpt_to}")

            server.sendmail(
                mail_from, rcpt_to, message
            )
        elif task["type"] == "batch":
            eprint("s")
        else:
            eprint(f"Task {task['type']} is not valid. Skipping")

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
