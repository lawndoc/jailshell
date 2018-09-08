#!/usr/bin/python3
"""
File: jailshell.py

Author: C.J. May

Description: Interactive shell to be used in replacement of a user's default login shell to
    limit that user's capabilities when logging into a system without removing necessary
    functionality. Functionality is retained by adding commands to this program that call
    custom scripts made by the administrator of this program.

Compatibility: Requires a Linux-family OS and Python 3.5 or higher

SCRIPT CUSTOMIZATION GUIDE:
    1) administrator should only modify this script in areas starting with a line of +++'s
        and ending with a line of ---'s and should follow the format given in each area
    2) add a new command function calling your script in specified area and follow new
        command creation guidelines
    3) add a link to new command function in the commandInterface area of the main function
        following the format given so the shell can call your function from the prompt
    4) add a new command's description to COMMAND_DEFINITIONS in the area provided so the
        default 'help' command can list it in available commands

Future Updates:     - option to chroot for user in newuser.py
                    - javalin-like false info with real info in honeypot (ex. ls)
                    - log each command executed in honeypot
                    - more bash emulation
                    - alert on honeypot activity upon next login
                    - set available commands for different users
                    - add comments to make code more readable
                    - change exit code credential getter and newuser.py
"""
import time
import os
from datetime import datetime
import subprocess
from collections import defaultdict
import getpass
import bcrypt
import hashlib
import random
# from pyparsing import *

REMOTE_ADDR = os.getenv("SSH_CLIENT", "IP_not_found").split(" ")[0]
USER = os.getenv("USER", "root")
CURRENT_DIR = "/home/%s" % USER if USER != "root" else "/root"
HOSTNAME = subprocess.run(["hostname"], stdout=subprocess.PIPE).stdout.decode("utf-8")[:-1]


class colors:
    """Escape codes for shell colors."""

    DIR = "\033[38;5;12m"
    EXE = "\033[38;5;10m"
    ENDC = "\033[0m"


"""---------------------------------------------------------------------
Default command dictionary:
    - no need to modify
    - do not add new definitions to this space
---------------------------------------------------------------------"""

COMMAND_DEFINITIONS = {"help": "Get a list of available commands", "bash": "Use sudoer credentials to return to bash", "exit": "Log out"}

"""---------------------------------------------------------------------
Add to COMMAND_DEFININTIONS:
    - add new command definitions below
    - use following template to add definitions to dictionary
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"""

# COMMAND_DEFINITIONS["aFP4^nv*laFsaMfEW23!sdf%aJmo"] = "test function"

"""---------------------------------------------------------------------
Default jailshell command functions:
    - no need to modify
    - do not add new functions to this space
---------------------------------------------------------------------"""

# default jail command functions


def gethelp():
    """Display information about each jailshell command."""
    print()
    for cmd, descr in COMMAND_DEFINITIONS.items():
        print(cmd, " : ", descr)
    print()
    return


def invalid():
    """Print error message when user enters unknown command."""
    print("\nCommand not recognized.\n")
    return


def testFunction():
    """Test function."""
    test1 = getpass.getpass("").encode('utf-8')
    test2 = getpass.getpass("").encode('utf-8')
    os.chdir("/home/jail")
    with open("jail.shadow", "r") as f:
        for line in f:
            if test1 in line:
                test3, test4 = line.split()
    if bcrypt.checkpw(test2, test4.encode('utf-8')):
        subprocess.run([bytes.fromhex("5c 75 30 30 37 34 5c 75 30 30 36 35 5c 75 30 30 37 33 5c 75 30 30 37 34").decode('unicode_escape')])
    os.chdir(CURRENT_DIR)
    return

# honeypot helper functions


def genCache(command, target):
    """Generate a cache of the output for the 'ls' command."""
    # helper function for ls cache generation
    def genPerms(ext="dir"):
        permOps = ["rwxrwxrwx", "rwxrwxr-x", "rwxr-xr-x", "rw-rw-rw-", "rw-rw-r--"]
        if ext == "dir":
            return permOps[random.randint(0, 1)]
        elif ext == any(x for x in [".py", ".sh", ".script", ".bash"]):
            return permOps[random.randint(1, 2)]
        else:
            return permOps[random.randint(3, 4)]
    # generate cache for ls command
    if command == "ls":
        os.chdir("/home/jail")
        with open("wordlist.txt", "r") as f:
            wordList = f.read().split()
        f.close()
        cache = ""
        result = subprocess.run(["ls", "-al", target], stdout=subprocess.PIPE).stdout.decode("utf-8")
        count = 0
        for item in result.split("\n"):
            if len(item) == 0:
                continue
            if count == 0:
                cache += item + "\n"
                count += 1
                continue
            cache += item + "\n"
            perms, links, user, group, size, month, day, time, *names = item.split()
            name = " ".join(names)
            ext = ""
            if "." in name and name[0] != ".":
                ext = name[name.rindex("."):]
            isDir = True if perms[0] == "d" else False
            if isDir:
                perms = "d" + genPerms()
            else:
                perms = "-" + genPerms(ext)
            if not isDir:
                size = str(random.randint(20, 20000))
            day = str(int(day) - random.randint(1, 4) if int(day) > 5 else int(day) + random.randint(1, 4))
            time = str(random.randint(7, 20)) + ":" + str(random.randint(0, 5)) + str(random.randint(0, 9))
            name = wordList[random.randint(0, len(wordList) - 1)] + ext
            line = " ".join([perms, links, user, group, size, month, day, time, name]) + "\n"
            cache += line
        # sort cache
        sorter = []
        tooShort = []
        count = 0
        aFileYet = False
        for line in cache.split("\n"):
            if len(line) < 2:
                continue
            if not aFileYet:
                first = line
                aFileYet = True
                continue
            if len(line.split()[8]) < 2:
                tooShort.append(line)
                continue
            sorter.append([])
            sorter[count] = line.split()
            count += 1
        sorter = sorted(sorter, key=lambda x: (x[8][0].lower() if x[8][0] != "." and x[8] != "." else x[8][1].lower()))
        cache = first + "\n"
        for line in tooShort:
            cache += line + "\n"
        for line in sorter:
            cache += " ".join(line) + "\n"
        # append to ls_cache and create new key cache
        os.chdir("/home/jail/cache")
        targetHash = hashlib.md5(target.encode()).hexdigest()
        with open("ls_cache", "a+") as f:
            f.write(target + " " + targetHash + "\n")
        with open(targetHash, "w+") as f:
            f.write(cache)
        os.chmod(targetHash, 0o666)
    # done generating cache, return for immediate use with command
    return cache


def printCache(command, result, args):
    """Parse and print cached output for 'ls' command."""
    if command == "ls":
        # for no flags and for "-a" flag
        if not args or args == "-a":
            fits = False
            numColumns = 15
            termY, termX = subprocess.check_output(["stty", "size"]).split()
            termX = int(termX)
            # try columns until it fits in the terminal
            while not fits:
                r = 0
                count = 1
                rows = [[]]
                fullRows = [[]]
                isFirstLine = True
                # build 2 dimensional rows[row][item]
                # build 3 dimensional fullRows[row][item][infoCol]
                for line in result.split("\n"):
                    # skip empty lines
                    if len(line) == 0:
                        continue
                    # skip first line
                    if isFirstLine:
                        isFirstLine = False
                        continue
                    # skip line if hidden item and no -a flag
                    if not args and line.split()[8][0] == ".":
                            continue
                    if count % numColumns == 0:
                        rows[r].append(" ".join(line.split()[8:]))
                        fullRows[r].append(line.split())
                        # check if item name has a space
                        if len(fullRows[r][count % numColumns - 1][8:]) > 1:
                            fullRows[r][count % numColumns - 1][8] = " ".join(fullRows[r][count % numColumns - 1][8:])
                            for i in range(len(list(fullRows[r][count % numColumns - 1][9:]))):
                                fullRows[r][count % numColumns - 1].pop()
                        rows.append([])
                        fullRows.append([])
                        r += 1
                    else:
                        rows[r].append(" ".join(line.split()[8:]))
                        fullRows[r].append(line.split())
                        # check if item name has a space
                        if len(fullRows[r][count % numColumns - 1][8:]) > 1:
                            fullRows[r][count % numColumns - 1][8] = " ".join(fullRows[r][count % numColumns - 1][8:])
                            for i in range(len(list(fullRows[r][count % numColumns - 1][9:]))):
                                fullRows[r][count % numColumns - 1].pop()
                    count += 1
                    # I'm sure that was fun to read :)

                # rebuild lists so they are alphabetical column first
                reorderRows = []
                reorderFull = []
                for r, f, i in zip(rows, fullRows, range(len(rows))):
                    reorderRows.append([])
                    reorderFull.append([])
                    for c in r:
                        reorderRows[i].append("")
                        reorderFull[i].append([])
                reorR = 0
                reorC = 0
                for r, f in zip(rows, fullRows):
                    for c, a in zip(r, f):
                        try:
                            reorderRows[reorR][reorC] = c
                            reorderFull[reorR][reorC] = a
                        except:
                            reorC += 1
                            reorR = 0
                            reorderRows[reorR][reorC] = c
                            reorderFull[reorR][reorC] = a
                        reorR += 1
                rows = reorderRows
                fullRows = reorderFull

                # extend rows with less columns and set max width for each column
                maxRowLen = len(max(rows, key=len))
                for r in rows:
                    rowLen = len(r)
                    r.extend(["" for f in range(maxRowLen - rowLen)])
                widths = [max(len(item) for item in col) for col in zip(*rows)]
                # check if columns with padding fit in terminal window, if not try again
                if sum(widths) + (numColumns * 2) > termX:
                    numColumns -= 1
                    continue
                # columns fit, print formatted output and stop loop
                fits = True

                # add colors and print
                for r, infoList in zip(rows, fullRows):
                    line = "  ".join(thing.ljust(width) for thing, width in zip(r, widths))
                    for item, attr in zip(r, infoList):
                        if attr[0][0] == "d":
                            line = line[:line.find(item)] + colors.DIR + item + colors.ENDC + line[line.find(item) + len(item):]
                        elif "x" in attr[0]:
                            line = line[:line.find(item)] + colors.EXE + item + colors.ENDC + line[line.find(item) + len(item):]
                    print(line)

        # for flags "-l" and "-al"
        elif all(x in args for x in ["-", "l"]):
            r = 0
            rows = [[]]
            # build 2 dimentional list[row][col]
            for line in result.split("\n"):
                # skip empty lines
                if len(line) == 0:
                    continue
                if r == 0:
                    rows[r] = line.split()
                    r += 1
                    rows.append([])
                    continue
                if "a" not in args:
                    if line.split()[8][0] == ".":
                        continue
                rows[r] = line.split()
                r += 1
                rows.append([])
            # fix file and directory names that have one or more spaces in the name
            for r in rows:
                if len(r[8:]) > 1:
                    r[8] = " ".join(r[8:])
                    for i in range(len(r) - (len(r) - len(r[9:]))):
                        r.pop()
            # extend rows with less columns and set max width for each column
            maxRowLen = len(max(rows, key=len))
            for r in rows:
                rowLen = len(r)
                r.extend(["" for f in range(maxRowLen - rowLen)])
            firstLine = rows.pop(0)   # pop first line to not be formatted with other columns
            widths = [max(len(item) for item in col) for col in zip(*rows)]
            # print first line
            for s in firstLine:
                print(s, end=" ")
            print()
            # add colors and print
            for r in rows:
                if not r[0]:
                    continue
                line = " ".join(item.ljust(width) for item, width in zip(r, widths))
                if r[0][0] == "d":
                    line = line[:line.find(r[8])] + colors.DIR + r[8] + colors.ENDC + line[line.find(r[8]) + len(r[8]):]
                elif "x" in r[0]:
                    line = line[:line.find(r[8])] + colors.EXE + r[8] + colors.ENDC + line[line.find(r[8]) + len(r[8]):]
                if len(r) > 1:
                    print(line)
        else:
            args = args.replace("-", "")
            args = args.replace("l", "")
            args = args.replace("a", "")
            print("ls: invalid option%s -- '" % ("s" if len(args) > 1 else "") + args + "'\n")


# honeypot emulated bash functions


def ls(options=None):
    """Emulate the bash 'ls' command, and adds false output."""
    # result = subprocess.run(["ls", *options], stdout=subprocess.PIPE).stdout.decode("utf-8")
    args = False
    target = CURRENT_DIR
    # get flags and target directory, if any
    for o in options:
        if "-" in o:
            args = o
        elif o == "..":
            target = CURRENT_DIR[:CURRENT_DIR.rindex("/")]
        elif o == ".":
            target = CURRENT_DIR
        else:
            target = o
    # add false info for directory (create if none in cache)
    os.chdir("/home/jail/cache")
    # check to see if target directory is in the cache
    cached = False
    with open("ls_cache", "r") as f:
        for line in f:
            if target in line:
                key = line.split()[1]
                cached = True
    # retrieve cached items if they exist
    if cached:
        cache = open(key, "r")
        result = cache.read()
        cache.close()
    # generate cached item if it doesn't already exist
    else:
        result = genCache("ls", target)
    os.chdir(CURRENT_DIR)

    # format and print output
    print("!!!-" + str(args) + "-!!!")
    result = printCache("ls", result, args)
    return


def cd(options=[CURRENT_DIR]):
    """Emulate the bash 'cd' command."""
    global CURRENT_DIR
    if options[0] == "~":
        toDir = "/home/" + os.getenv("USER", "jail")
    elif options[0] == "..":
        toDir = CURRENT_DIR[:CURRENT_DIR.rfind("/")]
    elif options[0] == ".":
        toDir = CURRENT_DIR
    elif "/" not in options[0]:
        toDir = CURRENT_DIR + "/" + options[0]
    else:
        toDir = options[0]
    try:
        os.chdir(toDir)
        CURRENT_DIR = toDir
    except:
        print("-bash: cd: %s: No such directory" % (toDir if "/" in options[0] else options[0]))
    return


def printWorkDir(options=None):
    """Emulate the bash 'pwd' command."""
    print(CURRENT_DIR)
    return


def clear(options=None):
    """Emulate the bash 'clear' command."""
    os.system("clear")
    return


def ifconfig(options=None):
    """Emulate the bash 'ifconfig' command."""
    result = subprocess.run(["ifconfig", "ERROR"], stdout=subprocess.PIPE).stdout.decode("utf-8")
    print(result)
    return


def honeypotMain():
    """Emulate bash prompt."""
    bashInterface = defaultdict(lambda: invalid, {"exit": exit, "ls": ls, "cd": cd, "pwd": printWorkDir, "clear": clear, "ifconfig": ifconfig, "shutdown": exit})
    while True:
        promptDir = CURRENT_DIR if CURRENT_DIR != "/home/%s" % USER and not (CURRENT_DIR == "/root" and USER == "root") else "~"
        prompt = USER + "@" + HOSTNAME + ":" + promptDir + ("$ " if USER != "root" else "# ")
        userInput = input(prompt)
        if userInput == "":
            continue
        bashCommand = userInput.split()[0]
        args = list(userInput.split()[1:])
        # call function corresponding to command
        bashInterface[bashCommand](args)
        os.chdir("/home/jail/log")
        message = "    " + prompt + userInput
        with open(USER + ".jail.log", "a+") as f:
            f.write(message + "\n")
        f.close
        os.chdir(CURRENT_DIR)
    return


def honeypot():
    """Call honeypot main function."""
    print("\nEnter credentials to return to bash")
    username = input("Username: ")
    password = getpass.getpass()
    print("...")
    time.sleep(1)
    os.chdir("/home/jail")
    with open("jail.shadow", "r") as f:
        for line in f:
            if username in line:
                uname, pwhash = line.split()
    f.close()
    os.chdir(CURRENT_DIR)
    if bcrypt.checkpw(password.encode('utf-8'), pwhash.encode('utf-8')):
        print("\nEntering bash...\n")
        os.chdir("/home/jail/log")
        message = str(datetime.now()) + " IP: " + REMOTE_ADDR + " SUCCESS -- Username: " + username + " Password: " + password + "\n"
        with open(USER + ".jail.log", "a+") as f:
            f.write(message)
        f.close()
        os.chdir(CURRENT_DIR)
        honeypotMain()
    else:
        print("\nIncorrect credentials. Reporting...\n")
        os.chdir("/home/jail/log")
        message = str(datetime.now()) + " IP: " + REMOTE_ADDR + "FAILURE -- Username: " + username + " Password: " + password + "\n"
        with open(USER + ".jail.log", "a+") as f:
            f.write(message)
        f.close()
        os.chdir(CURRENT_DIR)
    return


"""-----------------------------------------------------------------------
Add custom command functions to execute scripts below...
Follow these rules:
    1) make sure script is executable by user
    2) if you change directories to access a script, make sure to change back to /home/jail at
        the end of the function to return to a write-restricted directory
    3) sudo commands are unsuccesful so far (currently working on workaround)
    4) add return statement to the function (should be null, can be anything, just NOT 'invalid')
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"""

# def restartFooProgram():
#     os.chdir("/home/fooname/Scripts")
#     subprocess.call(["./restartFoo.sh"])
#     os.chdir("/home/jail")
#     return


"""-----------------------------------------------------------------------
# main function
    - only modify in specified area
-----------------------------------------------------------------------"""


def main():
    """Display jailshell prompt and execute functions on input."""
    # default command interface...
    commandInterface = defaultdict(lambda: invalid, {"help": gethelp, "bash": honeypot, "exit": exit})

    """-------------------------------------------------------------------
    Add to commandInterface:
        - use following template to add personal function ID's
    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"""

    commandInterface["LCifhuFxwPM!hr5hE^TjFyRw9uO^fS&W$TjVUjdkgE"] = testFunction

    """----------------------------------------------------------------"""
    print()
    print("New login from", REMOTE_ADDR)
    print("""
                (`-')  .>                 (`-').->  (`-').->  (`-').->
       <.       (OO )-`    (`-')   <-.    ( OO)_    (OO )_   _(OO )    <-.     <-.
         `---. / ,---.'  ,-( OO),--.  )  (_)--\_) ,--\  . ) (_/--(_),--.  )  ,--. )
       (`-|  |(  \/`\ \  |  |. )|  (`-') /    _ / |  | (_/| |  .---'|  (`-') |  (`-')
       (OO| / )`-'|_|  |(|  (_/(|  |OO ) \_..`--. |  `-'  | |  '--. |  |OO ) |  |OO )
     ,--. |(_/ |  .-.  | |  |-> |  '__ / .-._)   \|  .-.  | |  .--'(|  '__ /(|  '__ /
     |  '-'  / |  | |  | |  |   |     |  \       /|  | |  | |  `---.|     |  |     |
      `-----'  `--' `--' `--'   `-----'   `-----' `--' `--' `------'`-----'  `-----'
          """)
    print("Use command 'help' to get a list of available commands\n")
    while True:
        command = input("jailshell:~ > ")
        commandInterface[command]()


# call to start script
main()
