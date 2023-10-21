import hashlib  # Import hashlib library for password hashing
import tkinter  # Import tkinter for the graphical user interface
import requests  # Import requests library for making HTTP requests

# Create a tkinter window for the password checker application
window = tkinter.Tk()
window.title("Password Checker")
window.geometry("400x200")


# Define a function to request data from the Pwned Passwords API
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        # If there is an error when fetching data from the API, raise a RuntimeError
        raise RuntimeError(f"Error fetching: {res.status_code}, check "
                           f"the api and try again")
    return res


# Define a function to get the count of password leaks from the API response
def get_password_leaks_count(hashes, hash_to_check):
    # Split the response into lines and then into pairs of hash and coun
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# Define a function to check if a password has been compromised using the Pwned Passwords API
def pwned_api_check(password):
    # Hash the provided password using SHA-1
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # Extract the first 5 characters of the hash (prefix) and the rest (tail)
    first5_char, tail = sha1password[:5], sha1password[5:]
    # Request data from the API using the prefix and check for password leaks
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


# Define a function to check the password when the "Check Password" button is clicked
def check_password():
    password = password_entry.get() # Get the password entered by the user
    count = pwned_api_check(password)
    if count:
        # If the password is found in the API response, inform the user
        result_text.set(f"Your password was found {count} times... \n"
                        f"You should probably change your password ")
    else:
        result_text.set(f"Your password was NOT found. You are good to go!")


# Function to clear the entry field
def clear():
    password_entry.delete(0, tkinter.END)


# GUI elements
password_label = (tkinter.Label(window, text="Enter a password: "))
password_label.pack()

password_entry = tkinter.Entry(window, width=20, show="*") # The password will be shown as "*"
password_entry.pack()

Button = tkinter.Button(window, text="Check Password", command=check_password)
Button.pack()

clear_button = tkinter.Button(window, text="Clear", command=clear)
clear_button.pack()

result_text = tkinter.StringVar()
result_label = tkinter.Label(window, textvariable=result_text)
result_label.pack()

# Start the application
window.mainloop()
