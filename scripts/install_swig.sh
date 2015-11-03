#!/bin/bash

#
# Script to install Swig and its prereqs
#

# DIRNAME=/usr/bin/dirname
# READLINK=/bin/readlink
# READLINKF="${READLINK} -f"

# DNCMD='${DIRNAME} "$(${READLINKF} \"$0\")"'
# SCRIPT_DIR=$(eval $DNCMD)

# . ${SCRIPT_DIR}/scripts_profile
UNAME=/bin/uname
MAKE=/usr/bin/make
CURL=/usr/bin/curl
MKDIR=/bin/mkdir
TAR=/bin/tar
RM=/bin/rm
OPENSSL_CMD=/usr/bin/openssl
LN="/bin/ln -sf"

get_os() {
	local KERNELV=$(${UNAME} -v)
	local FLAVOR=${KERNELV#*-}
	FLAVOR=${FLAVOR%% *}
	printf $FLAVOR
}

# called if we encounter a fatal error
fatal() {
	log "FATAL" "$1"
	exit 0
}

error() {
	log "ERROR" "$1"
}

warn() {
	log "WARN" "$1"
}

log() {
	local SEVERITY=$1
	local MSG=$2
	printf "%(%F %T)T" -1
	printf "\t%-7s %s\n"  "$SEVERITY" "$MSG"
}

#
# Download PCRE 8.37 (we've had issues with PCRE2 and swig compatibility)
#

WORKDIR=/tmp/install_swig.$$
if [[ $# -ge 1 ]]; then
	INSTALL_PREFIX=$1
else
	INSTALL_PREFIX=/usr/local
fi

log "INFO" "Installing SWIG and PCRE under $INSTALL_PREFIX"

${MKDIR} ${WORKDIR} || fatal "Unable to create ${WORKDIR}"
cd ${WORKDIR} 

TARGZ=.tar.gz
PCRE_URL_BASE=http://downloads.sourceforge.net/project/pcre/pcre/
PCREREL=8.37
# /pcre-8.37.tar.gz?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fpcre%2Ffiles%2Fpcre%2F8.37%2F&ts=1446483191&use_mirror=superb-dca2
PCRE=pcre-${PCREREL}
PCREPKG=${PCRE}${TARGZ}
$CURL -O -L "${PCRE_URL_BASE}${PCREREL}/${PCREPKG}"

#
# Download SWIG
#

# SWIG_URL_BASE=http://prdownloads.sourceforge.net/swig/
SWIG_URL_BASE=http://downloads.sourceforge.net/project/swig/swig/
SWIGREL=3.0.7
DL_REFERRER="r=http\%3A\%2F\%2Fsourceforge.net\%2Fprojects\%2Fswig\%2Ffiles\%2F\&ts=1446482403\&use_mirror=iweb"

SWIG=swig-${SWIGREL}
SWIGPKG=${SWIG}${TARGZ}


# $CURL -O "${SWIG_URL_BASE}${SWIG}/${SWIGPKG}?${DL_REFERRER}"
$CURL -O -L "${SWIG_URL_BASE}${SWIG}/${SWIGPKG}"

#
# Build
#

$TAR -xzf $PCREPKG
cd $PCRE || fatal "$PCREPKG - unable to extract source package"
./configure --prefix=${INSTALL_PREFIX}
$MAKE
$MAKE install

if [[ ! -x ${INSTALL_PREFIX}/bin/pcre-config ]]; then
	fatal "${INSTALL_PREFIX} not installed correctly, exiting"
fi

cd ${WORKDIR}
$TAR -xzf $SWIGPKG
cd $SWIG || fatal "$SWIGPKG - unable to extract source package"
./configure --prefix=${INSTALL_PREFIX}
$MAKE
$MAKE install
if [[ ! -x ${INSTALL_PREFIX}/bin/swig ]]; then
	fatal "${INSTALL_PREFIX}/bin/swig not installed correctly, exiting"
fi

log "INFO" "Installation of ${SWIG} complete"