from enum import Enum

# Script config
debug = 1

# SMTP target domain config
lookup_domain = 'mail.polimi.it'
helo_domain = 'polimi.it'

# pysmtp operation mode
tasks = [
    {
        "type": "single",
        "mail_from": "andrea.cioccarelli01@gmail.com",
        "rcpt_to": "andrea.cioccarelli@mail.polimi.it",
        "data":
        """
            Helo
        """
    },
    {
        "type": "single",
        "mail_from": "andrea.cioccarelli01@gmail.com",
        "rcpt_to": "andrea.cioccarelli@mail.polimi.it",
        "data":
        """
            Helo
        """
    },
    {
        "type": "loop",
        "mail_from": "andrea.cioccarelli01@gmail.com",
        "rcpt_to": "andrea.cioccarelli@mail.polimi.it"
    }
]