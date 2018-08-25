#!/usr/bin/python3
"""
File: newuser.py
Author: C.J. May
Description: Script to add users that can log into bash honeypot from jailshell.py
"""
import bcrypt
import getpass

def main():
    print("Creating a new user for bash honeypot.")
    username = input("Enter the name of user to be added: ")
    password = ""
    pswdCheck = "check"
    while password != pswdCheck:
        password = getpass.getpass("Enter a new password: ")
        pswdCheck = getpass.getpass("Verify new password: ")
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    with open("jail.shadow","a+") as f:
        f.write(username + " " + hashed.decode() + "\n")
    f.close()

main()
