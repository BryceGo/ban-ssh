# BAN-SSH: Automatic SSH Ban
[![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](./LICENSE)

# Description
Ban-SSH is an SSH monitoring python script that automatically bans IP addresses based on the number of attempts performed.
The program monitors the SSH auth log file usually located in /var/log/auth.log. The script will track the number of failed attempts associated with the IP address to the SSH server. If an IP addresses reaches the maximum number of attemtps, the script will "ban" the IP address by creating a netfilter rule against the IP address.

Depending on the setup, the script can unban an IP address after some time has passed.

# Environment
- Python 3.8.5
- Ubuntu 20.04 LTS

# Usage
Run the file using:
```
sudo python3 ban-ssh.py [-h] [-f FILE] [-d DATABASE] [-m MAX_ATTEMPTS] [-u UNBAN_LIMIT]
```

## Optional Arguments
- -h, --help 
    - shows the help message
- -f FILE, --file FILE      
    - specifies the auth.log file to track. Defaults to /var/log/auth.log
- -d DATABASE, --database DATABASE
    - the JSON database filename. 
    - Defaults to ./database
-   -m MAX_ATTEMPTS, --max_attempts MAX_ATTEMPTS
    - maximum number of SSH login attempts before the ban. -1 for no ban.
    - Default is 3
-   -u UNBAN_LIMIT, --unban_limit UNBAN_LIMIT
      - Unbanning time in minutes. -1 for indefinite. 
      - Default is -1. 
      - Ban occurs for unban_limit^(number of bans). 
      - This means ban time increases exponentially in max_attempt increments until a successful login is detected
# Notes
The user running the script must have access to read/write netfiltering rules.
In other words, the command ```iptables``` should be runnable by the user running the script.