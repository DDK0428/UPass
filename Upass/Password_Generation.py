import secrets
import string


def password_generator():
    u_letters = string.ascii_uppercase
    l_letters = string.ascii_lowercase
    numbers = string.digits
    s_chars = string.punctuation
    pwd_length = 16
    alphabet = u_letters + l_letters + numbers + s_chars
    while True:
        pwd = ''
        for i in range(pwd_length):
            pwd += ''.join(secrets.choice(alphabet))

        if any(char in u_letters for char in pwd) and any(char in l_letters for char in pwd) and \
                any(char in s_chars for char in pwd) and sum(char in numbers for char in pwd) >= 4:
            break
    return pwd

