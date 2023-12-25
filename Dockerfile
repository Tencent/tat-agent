FROM centos:7
ADD tat_agent /usr/local/bin
ADD utmpx /usr/local/bin
ENTRYPOINT ["/usr/local/bin/tat_agent","-n","-c"]
