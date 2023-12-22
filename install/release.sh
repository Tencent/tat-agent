#!/bin/bash
cd `dirname $0`
ARCH=$1
TAT_AGENT="tat_agent"
TAT_AGENT_32="tat_agent32"
TAT_AGENT_64="tat_agent64"
TAT_AGENT_AARCH64="tat_agent_aarch64"
ln -f ../${TAT_AGENT} ../${TAT_AGENT_32} ../${TAT_AGENT_AARCH64} .
# save to 64
cp -f ${TAT_AGENT} ${TAT_AGENT_64}

VERSION=`./${TAT_AGENT} --version | awk '{print $2}'`
if [ -z "${VERSION}" ]; then
    echo "${TAT_AGENT} version get failed, now exit"
    exit 1
fi
echo "${TAT_AGENT} version: ${VERSION}"

FILE_SUFFIX=".tar.gz"
INSTALL_FILE=${TAT_AGENT}_linux_install_${VERSION}${FILE_SUFFIX}
UNINSTALL_FILE=${TAT_AGENT}_linux_uninstall_${VERSION}${FILE_SUFFIX}

# clean old files.
rm -rf "${INSTALL_FILE}" "${UNINSTALL_FILE}"

# NOTE: mac tar do not support `--transform`, use gtar instead.
# generate install file for release
tar czf "${INSTALL_FILE}" install.sh ${TAT_AGENT} ${TAT_AGENT_32} ${TAT_AGENT_AARCH64} uninstall.sh test.sh tat_agent_service \
tat_agent.service tat_agent_service.conf --transform "s,^,${TAT_AGENT}_linux_install_${VERSION}/,"

# generate uninstall file for release
tar czf "${UNINSTALL_FILE}" uninstall.sh test.sh --transform "s,^,${TAT_AGENT}_linux_uninstall_${VERSION}/,"

# generate self update file for release (64bit)
# .zip file is used for self-update but can also be used to install agent
ARCH=x86_64
UPDATE_FILE="${TAT_AGENT}_linux_install_${ARCH}_${VERSION}.zip"
rm -rf "${UPDATE_FILE}"
zip "${UPDATE_FILE}" install.sh ${TAT_AGENT} uninstall.sh tat_agent_service tat_agent.service tat_agent_service.conf \
self_update.sh

# generate self update file for release (32bit)
# .zip file is used for self-update but can also be used to install agent
ARCH=i686
UPDATE_FILE_32="${TAT_AGENT}_linux_install_${ARCH}_${VERSION}.zip"
rm -rf "${UPDATE_FILE_32}"
# rename tat_agent_32 to tat_agent.
cp -f ${TAT_AGENT_32} ${TAT_AGENT}
zip "${UPDATE_FILE_32}" install.sh ${TAT_AGENT} uninstall.sh tat_agent_service tat_agent.service tat_agent_service.conf self_update.sh

# generate self update file for release (aarch64)
# .zip file is used for self-update but can also be used to install agent
ARCH=aarch64
UPDATE_FILE_AARCH64="${TAT_AGENT}_linux_install_${ARCH}_${VERSION}.zip"
rm -rf "${UPDATE_FILE_AARCH64}"
# rename tat_agent_aarch64 to tat_agent.
cp -f ${TAT_AGENT_AARCH64} ${TAT_AGENT}
zip "${UPDATE_FILE_AARCH64}" install.sh ${TAT_AGENT} uninstall.sh tat_agent_service tat_agent.service tat_agent_service.conf \
self_update.sh

# restore 64bit as default
cp -f ${TAT_AGENT_64} ${TAT_AGENT}

echo "release file generated:
${INSTALL_FILE}
${UNINSTALL_FILE}
${UPDATE_FILE}
${UPDATE_FILE_32}
${UPDATE_FILE_AARCH64}
"
