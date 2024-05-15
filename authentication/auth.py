import pyrebase
from colorama import init, Fore, Back, Style
from termcolor import cprint


firebaseConfig = {'apiKey': "AIzaSyD93v3JJazqqg95RZA3raqTu3qNFEtYYOI",
                  'authDomain': "securityproject-7a510.firebaseapp.com",
                  'projectId': "securityproject-7a510",
                  'storageBucket': "securityproject-7a510.appspot.com",
                  'messagingSenderId': "688231036937",
                  'appId': "1:688231036937:web:6ec8712f306b21819f20d8",
                  'measurementId': "G-WN8NKB7LKH"
                  }

firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()

init()
#flag = 0
def startUp():
    cprint("\t****WELCOME TO SECURITY SUITE 1.0****\t\n", "cyan", attrs=["dark"])
    cprint("\n  ____      _____      ____", "light_cyan")
    cprint("\n  \   \    /     \    /   /", "light_cyan")
    cprint("\n   \   \__/   _   \__/   /", "light_cyan")
    cprint("\n    \        / \        /" , "light_cyan")
    cprint("\n     \______/   \______/" , "light_cyan")


def signin():
    print("SIGN-IN")
    email = input("Email: ")
    password = input("Password: ")
    try:
        signin = auth.sign_in_with_email_and_password(email, password)
        #flag = 1
        print("Successfully signed in!")
        startUp()
    except:
        print("Incorrect email and/or password.")
    return 


def signup():
    print("SIGN-UP")
    email = input("Email: ")
    password = input("Password: ")
    #flag = 1
    try:
        user = auth.create_user_with_email_and_password(email, password)
        ask = input("Do you want to login? [y/n]")
        if ask == 'y':
            signin()
    except:
        print("Email already used.")
    return


answer = input("Are you a new user? [y/n]")

if answer == 'n':
    signin()
elif answer == 'y':
    signup()
