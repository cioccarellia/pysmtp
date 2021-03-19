def strip_mail(address):
    return str(address).removeprefix("<").removesuffix(">")


def prefill(email_from, rcpt_to):
    """
    Returns a prefilled and parameterized version of the mail content.

    :param email_from: The email sender.
    :param rcpt_to: The email recipient.
    :return: Prefilled binary-encoded mail content
    """

    return f'From: "" <{strip_mail(email_from)}>\n' \
           f'To: "" <{strip_mail(rcpt_to)}>\n' \
           'Subject:\n' \
           'MIME-Version: 1.0\n' \
           'Content-Type: multipart/alternative; boundary="00000000000014802805bddf7290"\n' \
           '\n' \
           '--00000000000014802805bddf7290\n' \
           'Content-Type: text/plain; charset="UTF-8"\n' \
           'Content-Transfer-Encoding: quoted-printable\n' \
           'Content-Disposition: inline\n' \
           '\n' \
           'Helo\n' \
           '\n' \
           '--00000000000014802805bddf7290\n' \
           'Content-Type: text/html; charset="UTF-8"\n' \
           'Content-Transfer-Encoding: quoted-printable\n' \
           'Content-Disposition: inline\n' \
           '\n' \
           '<h1>Helo</h1>\n' \
           '\n' \
           '--00000000000014802805bddf7290--'.encode()
