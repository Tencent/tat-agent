#!/bin/bash
cd `dirname $0`

PID_FILE="/var/run/tat_agent.pid"

# install the agent binary
SERVICE_DIR="/usr/local/qcloud/tat_agent/"
PATH_DIR="/usr/local/bin/"
TAT_AGENT="tat_agent"
UTMPX="utmpx"
TAT_AGENT32="tat_agent32"
TAT_AGENT_AARCH64="tat_agent_aarch64"
UTMPX32="utmpx32"
UTMPX_AARCH64="utmpx_aarch64"


try_kill_by_pid() {
    if [ -f ${PID_FILE} ]; then
        PID=$(cat ${PID_FILE})
        kill ${PID} > /dev/null 2>&1
        sleep 0.1 || sleep 1
        rm -f ${PID_FILE}
    fi
}

has_systemd() {
    [[ `systemctl` =~ -\.mount ]] > /dev/null 2>&1 && return 0
    if systemctl 2>/dev/null | grep -e "-\.mount" > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

has_sysvinit() {
    if [ -f /etc/init.d/cron ] && [ ! -h /etc/init.d/cron ]; then
        return 0
    fi
    if [ -f /etc/init.d/crond ] && [ ! -h /etc/init.d/crond ]; then
        return 0
    fi
    which chkconfig > /dev/null 2>&1 && return 0
    which update-rc.d > /dev/null 2>&1 && return 0
    return 1
}

has_upstart() {
    which initctl > /dev/null 2>&1 || return 1
    if /sbin/init --version 2>/dev/null | grep upstart > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

install() {
    echo "try to install tat_agent"

    # if arch is 32bit and 32bit bin exists, rename `tat_agent32` to `tat_agent`
    # if arch is aarch64 and aarch64 bin exists, rename `tat_agent_aarch64` to `tat_agent`
    machine=$(uname -m)
    if [ "$machine" != "x86_64" ]; then
        if [ "$machine" != "aarch64" ] && [ -f "$TAT_AGENT32" ]; then
            mv ${TAT_AGENT} -f ${TAT_AGENT}64
            mv ${UTMPX} -f ${UTMPX}64
            mv ${TAT_AGENT32} -f ${TAT_AGENT}
            mv ${UTMPX32} -f ${UTMPX}
        elif [ -f "$TAT_AGENT_AARCH64" ]; then
            mv ${TAT_AGENT} -f ${TAT_AGENT}64
            mv ${UTMPX} -f ${UTMPX}64
            mv ${TAT_AGENT_AARCH64} -f ${TAT_AGENT}
            mv ${UTMPX_AARCH64} -f ${UTMPX}
        fi
    fi

    # check if agent runnable
    chmod +x ${TAT_AGENT}
    chmod +x ${UTMPX}
    if ! ./${TAT_AGENT} -V; then
        echo "tat_agent not runnable, exit." >&2
        exit 1
    fi

    mkdir -p ${SERVICE_DIR}
    if [ $? -ne 0 ]; then
        # handle special case for CoreOS whose /usr is Read-only
        grep -q CoreOS /etc/os-release
        if [ $? -eq 0 ]; then
            SERVICE_DIR="/var/lib/qcloud/tat_agent/"
            mkdir -p ${SERVICE_DIR}
            PATH_DIR="/opt/bin/"
            sed -i 's/\/usr\/local\/qcloud/\/var\/lib\/qcloud/g' tat_agent.service tat_agent_service.conf tat_agent_service uninstall.sh
            sed -i 's/\/usr\/sbin/\/opt\/bin/g' uninstall.sh
        else
            echo 'Install failed, has no permission, may not root.' >&2
            exit 1
        fi
    fi
    cp -f ${TAT_AGENT} ${SERVICE_DIR}
    cp -f ${UTMPX} ${SERVICE_DIR}
    ln -sf ${SERVICE_DIR}${TAT_AGENT} ${PATH_DIR}${TAT_AGENT}

    if has_systemd; then
        echo "use systemd to manage service"
        SERVICE_FILE="tat_agent.service"

        # Set OOMPolicy for systemd >= v243
        systemd_version=$(systemctl --version | head -n 1 | awk '{print $2}')
        if [ "$systemd_version" -ge 243 ]; then
            sed -i 's/^# OOMPolicy=/OOMPolicy=/' ${SERVICE_FILE}
        fi

        SYSTEMD_DIR="/etc/systemd/system/"
        TARGET_FILE="${SYSTEMD_DIR}${SERVICE_FILE}"

        # Only copy the file and reload systemd configuration if the file doesn't exist or contents differ
        if [ ! -f "${TARGET_FILE}" ] || ! diff "${SERVICE_FILE}" "${TARGET_FILE}" > /dev/null; then
            cp -f "${SERVICE_FILE}" "${SYSTEMD_DIR}"
            systemctl daemon-reload
            systemctl enable "${SERVICE_FILE}"
        fi
    elif has_upstart; then
        echo "use upstart(initctl) to manage service"
        cp -f tat_agent_service.conf /etc/init/
    elif has_sysvinit; then
        cp -f tat_agent_service /etc/init.d/
        chmod 755 /etc/init.d/tat_agent_service
        which chkconfig > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo "use chkconfig to manage service"
            chkconfig --add tat_agent_service
            chkconfig tat_agent_service on
        else
          which update-rc.d > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "use update-rc.d to manage service"
                update-rc.d tat_agent_service defaults
            else
                echo "no proper daemon manager found, tat_agent can not auto start"
            fi
        fi
    else
        if test "${need_restart}" = true; then
            echo "no proper daemon manager found, tat_agent can not auto start"
            try_kill_by_pid
            cd ${SERVICE_DIR}
            ./${TAT_AGENT}
            echo "tat_agent started"
        fi
    fi
}

restart() {
    echo "try to restart tat_agent."
    if has_systemd; then
        echo "use systemd to manage service"
        systemctl restart tat_agent.service
    elif has_upstart; then
        echo "use upstart(initctl) to manage service"
        try_kill_by_pid
        initctl start tat_agent_service
    elif has_sysvinit; then
        /etc/init.d/tat_agent_service restart
    else
        try_kill_by_pid
        cd ${SERVICE_DIR}
        ./${TAT_AGENT}
        echo "tat_agent started"
    fi
}

start() {
    echo "try to start tat_agent."
    if has_systemd; then
        echo "use systemd to manage service"
        systemctl start tat_agent.service
    elif has_upstart; then
        echo "use upstart(initctl) to manage service"
        if ! initctl status tat_agent_service | grep -q "start/running"; then
            initctl start tat_agent_service
        fi
    elif has_sysvinit; then
        /etc/init.d/tat_agent_service start
    else
        cd ${SERVICE_DIR}
        ./${TAT_AGENT}
        echo "tat_agent started"
    fi
}

case $1 in
only_update)
    install
    ;;
restart)
    restart
    ;;
*)
    install
    start
    ;;
esac
