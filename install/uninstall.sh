#!/bin/bash
cd `dirname $0`

PID_FILE="/var/run/tat_agent.pid"
PID=0
if [ -e ${PID_FILE} ]; then
    PID=`cat ${PID_FILE}`
fi
SERVICE_DIR="/usr/local/qcloud/tat_agent/"
TAT_AGENT="tat_agent"
SYSTEMD_DIR="/etc/systemd/system/"

if [ -e ${SYSTEMD_DIR}tat_agent.service ]; then
    systemctl stop ${TAT_AGENT}
    rm -f ${SYSTEMD_DIR}tat_agent.service
    rm -f ${SYSTEMD_DIR}multi-user.target.wants/tat_agent.service
    systemctl daemon-reload
fi

if [ -e /etc/init/tat_agent_service.conf ]; then
    initctl stop tat_agent_service
    rm -f /etc/init/tat_agent_service.conf
fi

if [ -e /etc/init.d/tat_agent_service ]; then
    which chkconfig > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        chkconfig tat_agent_service off
        chkconfig --del tat_agent_service
    else
        which update-rc.d > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            update-rc.d -f tat_agent_service remove
        fi
    fi
    /etc/init.d/tat_agent_service stop
    rm -f /etc/init.d/tat_agent_service
fi

if [ ${PID} -ne 0 ]; then
    ps ${PID} | grep ${TAT_AGENT}
    if [ $? -eq 0 ]; then
        kill -9 ${PID}
    fi
fi

rm -f /usr/sbin/${TAT_AGENT}
rm -f ${PID_FILE}
rm -rf ${SERVICE_DIR}
echo "uninstall finished"
