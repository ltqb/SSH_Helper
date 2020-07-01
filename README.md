# SSH_Helper
Linux ssh scp remote tools

 -command string
    	ssh remote to run shell 
  -dest string
    	scp dest path to remote 
  -file string
    	hosts config to ssh
  -ip string
    	remote ip address to ssh
  -password string
    	the password to ssh remote
  -port int
    	remote port  to ssh (default 22)
  -src string
    	scp src path  to remote
  -user string
    	remote host user to ssh
  
EXAMPLES:
# SSH Remote to Run Shell
# ssh_helper --ip=192.168.1.1 --user=root --password="123456" --port=22 --command="df -h"
  
# SSH Remotes to Run Shell From Hosts Config
# ssh_helper --file="hostConfig.ini" --command="df -h"
  
# Copy File to Remote Like Scp
# ssh_helper --ip=192.168.1.1 --user=root --password="123456" --port=22  --src="/123.txt" --dest="/123.txt"
