# usu_command


## 完整shell
python -c "import pty;pty.spawn('/bin/bash')"
$ python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
$ stty raw -echo
$ fg
$ reset
$ export SHELL=bash
//$ export TERM=xterm-256color

## 加入到sudoer
echo "user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers