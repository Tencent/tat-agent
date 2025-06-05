#!/bin/bash

SERVICE_NAME="tat_install"
TAT_INSTALL_SERVICE_DIR="/usr/local/qcloud/tat_agent/install"
grep -q CoreOS /etc/os-release
if [ $? -eq 0 ]; then
    TAT_INSTALL_SERVICE_DIR="/var/lib/qcloud/tat_agent/install"
fi
INSTALL_DIR="${TAT_INSTALL_SERVICE_DIR}"
LOG_FILE="${TAT_INSTALL_SERVICE_DIR}/${SERVICE_NAME}.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> ${LOG_FILE}
}

detect_arch() {
    local arch=$(uname -m)
    case "$arch" in
        x86_64)
            echo "x86_64"
            ;;
        i386|i486|i586|i686)
            echo "i686"
            ;;
        aarch64|arm64)
            echo "aarch64"
            ;;
        *)
            echo "not supported"
            exit 1
            ;;
    esac
}

PRIMARY_DOMAIN="invoke.tat-tc.tencent.cn"
BACKUP_DOMAIN="invoke.tat-tc.tencentyun.com"
ARCH=$(detect_arch)

get_zip_url() {
    local domain=$1
    echo "https://${domain}/download?latest=true&arch=${ARCH}&system=linux"
}

detect_init_system() {
    if command -v systemctl  &>/dev/null ; then
        log "INIT_SYSTEM is systemd"
        echo "systemd"
    elif [[ -d /etc/init ]] && /sbin/init --version 2>&1 | grep -q upstart; then
        log "INIT_SYSTEM is upstart"
        echo "upstart"
    elif [[ -x /etc/init.d/procps ]]; then
        log "INIT_SYSTEM is sysvinit"
        echo "sysvinit"
    else
        log "INIT_SYSTEM is unknown"
        echo "unknown"
    fi
}

install_unzip() {
    if command -v unzip &>/dev/null; then
        log "unzip is already installed."
        return 0
    fi
    { command -v apt-get &>/dev/null && sudo apt-get update -qq && sudo apt-get install -y unzip; } ||
    { command -v apt-get &>/dev/null && sudo apt-get update -qq && sudo apt-get install -y --force-yes unzip; } ||
    { command -v dnf &>/dev/null && sudo dnf install -y unzip; } ||
    { command -v yum &>/dev/null && sudo yum install -y unzip; } ||
    { command -v zypper &>/dev/null && sudo zypper install -y unzip; } ||
    { command -v pacman &>/dev/null && sudo pacman -Sy --noconfirm unzip; } ||
    { command -v apk &>/dev/null && sudo apk add unzip; } ||
    { log "No supported package manager detected. Please install unzip manually." && return 1; }
}

register_service() {
    mkdir -p ${INSTALL_DIR}
    SCRIPT_NAME=$(basename $0)
    SCRIPT_PATH="${INSTALL_DIR}/${SCRIPT_NAME}"
    cp -f "$0" "${SCRIPT_PATH}"
    chmod +x "${SCRIPT_PATH}" 
    case $(detect_init_system) in
        systemd)
            log "install service as systemd"
            if [ -f /etc/systemd/system/${SERVICE_NAME}.service ]; then
                systemctl stop ${SERVICE_NAME}.service 2>/dev/null || true
                systemctl disable ${SERVICE_NAME}.service 2>/dev/null || true
            fi
            
            cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=TAT Installation Service
After=network.target

[Service]
Type=forking
ExecStart=/bin/bash -c "${SCRIPT_PATH} -service &"
WorkingDirectory=${INSTALL_DIR}
TimeoutStartSec=0
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable ${SERVICE_NAME}.service
            log "Registered service with systemd."
            ;;
        upstart)
            log "install service as upstart"
            if [ -f /etc/init/${SERVICE_NAME}.conf ]; then
                stop ${SERVICE_NAME} 2>/dev/null || true
                rm -f /etc/init/${SERVICE_NAME}.conf
            fi
            
            cat > /etc/init/${SERVICE_NAME}.conf <<EOF
description "TAT Installation Service"
start on runlevel [2345]
expect fork
exec ${SCRIPT_PATH} -service &
EOF
            log "Registered service with upstart."
            ;;
        sysvinit)
            log "install service as sysvinit"
            if [ -f /etc/init.d/${SERVICE_NAME} ]; then
                /etc/init.d/${SERVICE_NAME} stop 2>/dev/null || true
                update-rc.d -f ${SERVICE_NAME} remove 2>/dev/null || true
                rm -f /etc/init.d/${SERVICE_NAME}
            fi
            
            cat > /etc/init.d/${SERVICE_NAME} <<EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          ${SERVICE_NAME}
# Required-Start:    \$local_fs \$network
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:
# Short-Description: TAT Installation Service
### END INIT INFO

case "\$1" in
    start)
        ${SCRIPT_PATH} -service > /dev/null 2>&1 &
        echo "Service started in background. Check ${LOG_FILE} for installation progress."
        ;;
    *)
        echo "Usage: \$0 start" >&2
        exit 3
        ;;
esac
EOF
            chmod +x /etc/init.d/${SERVICE_NAME}
            update-rc.d ${SERVICE_NAME} defaults
            log "Registered service with sysvinit."
            ;;
    esac
}

uninstall_service() {
    case $(detect_init_system) in
        systemd)
            systemctl stop ${SERVICE_NAME}.service || true
            systemctl disable ${SERVICE_NAME}.service || true
            rm -f /etc/systemd/system/${SERVICE_NAME}.service
            systemctl daemon-reload
            log "Uninstalled service from systemd."
            ;;
        upstart)
            rm -f /etc/init/${SERVICE_NAME}.conf
            log "Uninstalled service from upstart."
            ;;
        sysvinit)
            update-rc.d -f ${SERVICE_NAME} remove
            rm -f /etc/init.d/${SERVICE_NAME}
            log "Uninstalled service from sysvinit."
            ;;
    esac
}

download_file() {
    local url=$1
    local output_file=$2
    local success=false

    if command -v wget &>/dev/null; then
        log "Using wget for download"
        if wget -q --no-check-certificate "${url}" -O "${output_file}"; then
            success=true
        fi
    elif command -v curl &>/dev/null; then
        log "Using curl for download"
        if curl -s -L --insecure "${url}" -o "${output_file}"; then
            success=true
        fi
    else
        log "Neither wget nor curl is available. Cannot download file."
        success=false
    fi

    echo $success
}

run_service() {
    log "Starting installation."

    mkdir -p ${INSTALL_DIR}
    
    local download_success=false
    local primary_url=$(get_zip_url ${PRIMARY_DOMAIN})
    local backup_url=$(get_zip_url ${BACKUP_DOMAIN})
    
    for i in {1..30}; do
        log "Trying primary domain (attempt $i): ${PRIMARY_DOMAIN}"
        download_success=$(download_file "${primary_url}" "${INSTALL_DIR}/installer.zip")
        if [ "$download_success" = true ]; then
            log "Downloaded installer successfully from primary domain."
            break
        fi
        
        log "Primary domain failed, immediately trying backup domain (attempt $i): ${BACKUP_DOMAIN}"
        download_success=$(download_file "${backup_url}" "${INSTALL_DIR}/installer.zip")
        if [ "$download_success" = true ]; then
            log "Downloaded installer successfully from backup domain."
            break
        fi
        
        log "Both domains failed on attempt $i, waiting before retry..."
        sleep 2
    done
    
    if [ "$download_success" = false ]; then
        log "Download failed after all attempts."
        exit 1
    fi
    log "download finish."

    install_unzip
    log "install unzip finish."

    unzip -qo ${INSTALL_DIR}/installer.zip -d ${INSTALL_DIR}/pkg
    log "unzip package finish."

    if [[ -x ${INSTALL_DIR}/pkg/install.sh ]]; then
        chmod +x ${INSTALL_DIR}/pkg/install.sh
        ${INSTALL_DIR}/pkg/install.sh >> ${LOG_FILE} 2>&1
        log "Installation script executed successfully."
    else
        log "Install script not found."
        exit 1
    fi

    log "Installation completed successfully."
}

case $1 in
    "-service")
        log "service started"
        run_service
        log "Uninstalling service..."
        uninstall_service
        ;;
    *)
        log "Registering service..."
        register_service
        log "Starting service..."
        case $(detect_init_system) in
            systemd) 
                log "start service use systemd"
                systemctl start ${SERVICE_NAME}.service 
                ;;
            upstart) 
                log "start service use upstart"
                start ${SERVICE_NAME} 
                ;;
            sysvinit) 
                log "start service use sysvinit"
                service ${SERVICE_NAME} start 
                ;;
            *) 
                log "start service directly..."
                run_service 
                ;;
        esac
        ;;
esac
