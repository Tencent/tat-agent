source /usr/local/qcloud/bash-precmd/bash-preexec.sh
preexec() { printf "\x1B\x50\x30\x2B\x24\x7E\x1B\x5C"; }
precmd()  { printf "\x1B\x50\x31\x2B\x24\x7E\x1B\x5C"; }
PS1="${PS1}\n"
