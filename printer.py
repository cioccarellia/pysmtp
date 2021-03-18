from colored import fg, bg, attr


def oprint(*messages):
    message = ""
    for token in messages:
        message += str(token)

    print(fg('blue') + attr('bold') + "[O] " + attr('reset') + str(message))


def dprint(*messages):
    message = ""
    for token in messages:
        message += str(token)

    print(fg('green') + attr('bold') + "[D] " + attr('reset') + str(message))


def wprint(*messages):
    message = ""
    for token in messages:
        message += str(token)

    print(fg('yellow') + attr('bold') + "[W] " + attr('reset') + str(message))


def eprint(*messages):
    message = ""
    for token in messages:
        message += str(token)

    print(fg('red') + attr('bold') + "[E] " + attr('reset') + str(message))

