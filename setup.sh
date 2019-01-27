#!/bin/bash

# install dependencies
echo "Installing dependencies...";
apt-get install -y python3 python3-pip build-essential libffi-dev python-dev ||
	dnf install -y python3 python3-pip build-essential libffi-dev python-dev ||
	yum install -y python3 python3-pip build-essential libffi-dev python-dev ||
	pacman -Syu --noconfirm python3 python3-pip build-essential libffi-dev python-dev ||
	echo -e "\nPackages could not be installed...\nPlease install the following packages or their equivalent manually:\n\npython3 python-pip python-dev build-essential libffi-dev\n";
pip3 install bcrypt;

# set up jailshell
echo "\nSetting up jailshell...";
mkdir -p /home/jail/log && mkdir /home/jail/cache && cp *.py /home/jail;
chmod -R 755 /home/jail && chown -R root:root /home/jail;
chmod 777 /home/jail/log && chmod 777 /home/jail/cache;
touch /home/jail/jail.shadow && touch /home/jail/cache/ls_cache;
cp wordlist.txt /home/jail && chmod 644 /home/jail/wordlist.txt;
echo -e "#!/bin/bash" > /usr/local/bin/test && chmod +x /usr/local/bin/test;
echo "bash;" >> /usr/local/bin/test;
echo "Done.";
echo "ATTENTION: THIS MESSAGE WILL ONLY APPEAR AFTER INSTALLATION:\nThis shell includes a secret exit code to actually enter bash that is disabled by default. This capability is added through the slightly obfuscated function 'testFunction' in jailshell.py that calls a script which was just created that calls bash. In the main function in jailshell.py, there is a commented out line that adds the exit code function caller to the command dictionary. If you uncomment it to enable the exit code, make sure to change the default 50-character exit code to your own secure code and keep the code in a password manager. When you enter the exit code, the prompt will be blank looking like the program is hung up, but you just need to enter valid credentials from any stored in jail.shadow. So enter username, hit enter, enter password, and hit Enter again. Again, this is disabled by default and this is the only time you will see any mention of this feature in any documentation. It is recommended to remove this script after it runs to erase all explicit traces of the exit code feature.";

