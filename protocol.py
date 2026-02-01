from login import handle_login, handle_register


def process_request(data):
    text = data.decode(errors="replace")

    if len(text) < 4:
        return "ERR"

    code = text[:3]
    payload = text[4:]

    try:
        user, pwd = payload.split("~", 1)
    except ValueError:
        return "ERR"

    if code == "log":
        return 'log~' + handle_login(user, pwd)

    if code == "reg":
        return 'log~' + handle_register(user, pwd)

    if code == "crt":
        data = payload.split('~')
        print(data)


    return "ERR"
