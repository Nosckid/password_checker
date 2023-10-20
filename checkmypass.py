import hashlib
import tkinter
import requests

window = tkinter.Tk()
window.title("Password Checker")
window.geometry("400x200")


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check "
                           f"the api and try again")
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # Check if the password exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def check_password():
    password = password_entry.get()
    count = pwned_api_check(password)
    if count:
        result_text.set(f"Your password was found {count} times... \n"
                        f"You should probably change your password ")
    else:
        result_text.set(f"Your password was NOT found. You are good to go!")


def clear():
    password_entry.delete(0, tkinter.END)


password_label = (tkinter.Label(window, text="Enter a password: "))
password_label.pack()

password_entry = tkinter.Entry(window, width=20, show="*")
password_entry.pack()

Button = tkinter.Button(window, text="Check Password", command=check_password)
Button.pack()

clear_button = tkinter.Button(window, text="Clear", command=clear)
clear_button.pack()

result_text = tkinter.StringVar()
result_label = tkinter.Label(window, textvariable=result_text)
result_label.pack()

window.mainloop()
