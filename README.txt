

           (`-')  .>                 (`-').->  (`-').->  (`-').->
  <.       (OO )-`    (`-')   <-.    ( OO)_    (OO )__  _(OO )    <-.     <-.
    `---. / ,---.'  ,-( OO),--.  )  (_)--\_) ,--\  . ) (_/--(_),--.  )  ,--. )
  (`-|  |(  \/`\ \  |  |. )|  (`-') /    _ / |  | (_/| |  .---'|  (`-') |  (`-')
  (OO| / )`-'|_|  |(|  (_/(|  |OO ) \_..`--. |  `-'  | |  '--. |  |OO ) |  |OO )
,--. |(_/ |  .-.  | |  |-> |  '__ / .-._)   \|  .-.  | |  .--'(|  '__ /(|  '__ /
|  '-'  / |  | |  | |  |   |     |  \       /|  | |  | |  `---.|     |  |     |
 `-----'  `--' `--' `--'   `-----'   `-----' `--' `--' `------'`-----'  `-----'
                                                                Written in Python v3


This script is an interactive shell that is meant to replace a user's default login
shell (usually bash). Therefore, whether logging into the machine physically or over 
remote connection, the computer is safe from malicious use by unsolicited users. The
purpose is to limit capability while still retaining required functionality. This is 
accomplished through the configurating user's addition of custom commands to execute 
scripts. 

This shell also includes a honeypot. The jailshell command "bash" is a bash shell
emulator that malicious users will try to use to escape jailshell. When invoked, it 
asks for credentials to log in (must match credentials in jail.shadow), and logs 
both authentication failures and successes. Once in the shell, each command (listed 
below) that is entered by the malicious user is also logged. See honeypot emulated 
bash commands for info on the commands available and to see the rest of the security 
features implemented with them.

The full repository in GitHub is not meant to be the environment that jailshell is
used. Instead, the environment needs to be set up separate from where the files are
downloaded. There is a script automating most of this process in the setup guide
below.

Instructions to set up and start using this shell are below:


SETUP GUIDE:
	1) $ sudo ./setup.sh		## (see below for info on script)
	2) change desired user(s) startup script from /bin/bash to /home/jail/jailshell.py 
		in the file /etc/passwd
	3) make sure to add the username and password to jail.shadow by executing 
		newuser.py which is now in the /home/jail directory
	4) add custom commands using the guide at the top of jailshell.py to execute your
		scripts from jailshell


The setup script creates a jailed environment /home/jail that is only writeable by root, 
as well as a directory for logs that will record honeypot access. It also moves all
necessary files (including the jailshell script) to /home/jail.

Default Jailshell Commands:
	- help: Gets a list of available commands and their definitions.
	- bash: Asks for user credentials and matches them to those stored in
		jail.shadow . If login is successful, the user enters an emulated
		bash environment with limited functionality. All login attempts to
		the honeypot are logged along with the remote IP (if through ssh),
		username tried, and password tried.
	- exit: Exits the session. Logs out if physically on the machine, and drops
		the connection if it is a remote login.

Honeypot -- Emulated Bash Commands:
	- ls		: displays the contents of a directory exactly like bash, but
				also includes fake contents that aren't actually there
	- cd		: changes the "current directory" variable in the script
	- pwd		: emulates bash command exactly
	- clear 	: emulates bash command exactly
	- ifconfig	: emulates bash command exactly

Honeypot Commands in Future Updates:
	- cat (real/fake) :: cached false info from fake (??and real??) files
	- ping (real)
	- touch (fake) :: add file to ls cache
	- > (fake) :: add data and filename to cat cache
	- su (fake)
	- ssh (fake)
	- shutdown (fake)
	- sudo (fake)


