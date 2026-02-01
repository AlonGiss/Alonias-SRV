from sqlHandler import SQLHandler

db = SQLHandler()


def handle_login(user, pwd):
    return "True" if db.check_login(user, pwd) else "False"


def handle_register(user, pwd):
    return "True" if db.register_user(user, pwd) else "False"
