#!/usr/bin/python3
"""
File: newuser.py
Author: C.J. May
Description: Script to add users that can log into bash honeypot from jailshell.py
"""
import bcrypt
import getpass
from sys import argv

def main():
    """Create a new user and store the hashed password in jail.shadow"""
    # check to see if there is a userlist
    if len(argv) > 1:
        flags = True
    else:
        flags = False
    valid = False
    if flags:
        if len(argv) == 3:
            if argv[1] == "-l":
                valid = True
            else:
                print("Invalid option. Either specify no options or \
                      use [-l <list.txt>] flag to specify a user list.")
        else:
            print("Invalid option. Either specify no options or \
                  use [-l <list.txt>] flag to specify a user list.")
    if flags and valid:
        with open(argv[2], "r") as accounts:
            for account in account:
                username, password = account.split(" ")
                hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                with open("jail.shadow", "a+") as shadow:
                    shadow.write(username + " " + hashed.decode() + "\n")
                print("Created account for " + username)
            print("Done. New accounts written to jail.shadow")
    else:
        print("Creating a new user for bash honeypot.")
        username = input("Enter the name of user to be added: ")
        password = ""
        pswdCheck = "check"
        while password != pswdCheck:
            password = getpass.getpass("Enter a new password: ")
            pswdCheck = getpass.getpass("Verify new password: ")
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        with open("jail.shadow", "a+") as shadow:
            shadow.write(username + " " + hashed.decode() + "\n")


main()
