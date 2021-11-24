#!/bin/bash
cd `dirname $0`
ARCH=$1
TAT_AGENT="tat_agent"
TAT_AGENT_32="tat_agent32"
ln -f ../${TAT_AGENT} ../${TAT_AGENT_32} .

VERSION=`./${TAT_AGENT} --version | awk '{print $2}'`
if [ -z "${VERSION}" ]; then
    echo "${TAT_AGENT} version get fail, now exit"
    exit 1
fi
echo "${TAT_AGENT} version: ${VERSION}"

FILE_SUFFIX=".tar.gz"
INSTALL_FILE=${TAT_AGENT}_linux_install_${VERSION}${FILE_SUFFIX}
UNINSTALL_FILE=${TAT_AGENT}_linux_uninstall_${VERSION}${FILE_SUFFIX}

# clean old files.
rm -rf "${INSTALL_FILE}" "${UNINSTALL_FILE}" "${UPDATE_FILE}" "${UPDATE_FILE_32}"

# NOTE: mac tar do not support `--transform`, use gtar instead.
# generate install file for release
tar czf "${INSTALL_FILE}" install.sh ${TAT_AGENT} ${TAT_AGENT_32} uninstall.sh test.sh tat_agent_service \
tat_agent.service tat_agent_service.conf --transform "s,^,${TAT_AGENT}_linux_install_${VERSION}/,"

# generate uninstall file for release
tar czf "${UNINSTALL_FILE}" uninstall.sh test.sh --transform "s,^,${TAT_AGENT}_linux_uninstall_${VERSION}/,"

# generate self update file for release (64bit)
ARCH=x86_64
UPDATE_FILE="${TAT_AGENT}_linux_update_${ARCH}_${VERSION}.zip"
zip "${UPDATE_FILE}" install.sh ${TAT_AGENT} uninstall.sh tat_agent_service tat_agent.service tat_agent_service.conf \
self_update.sh

# generate self update file for release (32bit)
ARCH=i686
UPDATE_FILE_32="${TAT_AGENT}_linux_update_${ARCH}_${VERSION}.zip"
# rename tat_agent_32 to tat_agent.
mv -f ${TAT_AGENT_32} ${TAT_AGENT}
zip "${UPDATE_FILE_32}" install.sh ${TAT_AGENT} uninstall.sh tat_agent_service tat_agent.service tat_agent_service.conf self_update.sh

# clean
rm -rf ${TAT_AGENT} ${TAT_AGENT_32}
echo "release file generated:
${INSTALL_FILE}
${UNINSTALL_FILE}
${UPDATE_FILE}
${UPDATE_FILE_32}
"
