#!/bin/bash

UNAME=/bin/uname
MAKE=/usr/bin/make
CURL=/usr/bin/curl
MKDIR=/bin/mkdir
TAR=/bin/tar
RM=/bin/rm
OPENSSL_CMD=/usr/bin/openssl
LN="/bin/ln -sf"

WORKDIR=/tmp/install_openssl.$$
LOGFILE=/tmp/install_openssl_log.$$

DL_URL=https://www.openssl.org/source/
CURL_CMD="${CURL} -# -O ${DL_URL}"
OSSL_REL=1.0.2d
FIPS_REL=2.0.10

OSSL=openssl-${OSSL_REL}

# Installation paths
if [[ $# -ge 1 ]]; then
	I_BASE=$1
else
	I_BASE=/usr/local
fi
export FIPSDIR=${I_BASE}/ssl/fips-2.0

OSSL_PREFIX=${I_BASE}/${OSSL}
OSSL_CONFIG="./config --prefix=${OSSL_PREFIX} fips shared"

#
# Whoops, bug here
#

if [[ $1 = "ecp" ]]; then
	FIPS=openssl-fips-ecp-${FIPS_REL}
else
	FIPS=openssl-fips-${FIPS_REL}
fi

cleanup() {
	local WD=$1
	cd /tmp
	log "INFO" "Removing working directory ${WD}"

	if [[ $WD != "/tmp/install_openssl*" ]]; then
		error "${WD} does not appear to be a valid working directory"
	else
		$RM -rf $WD && log "INFO" "Working directory ${WD} removed"
	fi
}

cleanup_install() {
	local INDIR=$1
	if [[ $INDIR != "" ]]; then

		# Installation failed, so remove the install dir, too
		if [[ ! -d $INDIR ]]; then
			error "${INDIR} not a directory, unable to uninstall"
		elif [[ $INDIR != "*/${OSSL}" && $INDIR != "*/${FIPS}" ]]; then
			error "${INDIR} does not appear to be a valid OpenSSL installation"
		else
			$RM -rf $INDIR
			log "INFO" "Installation at ${INDIR} removed"
		fi
	fi
}

# Return the OS, e.g. "Ubuntu"
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

verify_checksum() {
	local PKG=$1
	local R=$2
	local S=1
	log "INFO" "Retrieving checksum with ${CURL} ${DL_URL}${PKG}.sha1"
	local SHA1=$(${CURL} ${DL_URL}${PKG}.sha1)
	local SHA1_LOCAL=$(${OPENSSL_CMD} sha1 ${PKG})
	SHA1_LOCAL=${SHA1_LOCAL##*= }

	if [[ $SHA1 != $SHA1_LOCAL ]]; then
		warn "Downloaded checksum (${PKG}): ${SHA1}"
		warn "Calculated checksum (${PKG}): ${SHA1_LOCAL}"
		S=0
	else
		log "INFO" "Downloaded checksum (${PKG}): ${SHA1}"
		log "INFO" "Calculated checksum (${PKG}): ${SHA1_LOCAL}"
	fi

	eval $R="'$S'"
}


#
# Main body
# 

log "INFO" "Using ${LOGFILE} as log file"
log "INFO" "Using ${LOGFILE}.err as stderr log file"

$MKDIR $WORKDIR
exec 1> $LOGFILE
exec 2> ${LOGFILE}.err

log "INFO" "Using ${LOGFILE} as log file"

OS=$(get_os)

# For now, we only support Ubuntu
if [[ $OS != "Ubuntu" ]]; then
	# We'll need something better than this...
	# Should be a case/esac when we support other OSes
	fatal "Unsupported operating system: ${OS}"
fi

if [[ ! -x $CURL || ! -x $MAKE || ! -x $OPENSSL_CMD ]]; then
	fatal "Missing dependency, unable to proceed"
fi

cd $WORKDIR || fatal "Unable to cd to working directory ${WORKDIR}"

log "INFO" "Downloading ${OSSL} source package with ${CURL_CMD}${OSSL}.tar.gz"
${CURL_CMD}${OSSL}.tar.gz
log "INFO" "Downloading ${FIPS} source package with ${CURL_CMD}${FIPS}.tar.gz"
${CURL_CMD}${FIPS}.tar.gz

log "INFO" "Verifying package checksums"

verify_checksum ${OSSL}.tar.gz RET
if [[ $RET -ne 1  ]]; then
	fatal "Checksums do not match for ${OSSL}.tar.gz"
fi

verify_checksum ${FIPS}.tar.gz RET
if [[ $RET -ne 1  ]]; then
	fatal "Checksums do not match for ${FIPS}.tar.gz"
fi

log "INFO" "Checksums validated, proceeding"

log "INFO" "Creating installation directories and symlinks"

if [[ -d ${OSSL_PREFIX} ]]; then
	fatal "${OSSL_PREFIX} exists already, exiting"
fi

$MKDIR -p ${OSSL_PREFIX} || fatal "Unable to create installation directory ${OSSL_PREFIX}"

if [[ -e ${I_BASE}/ssl && -L ${I_BASE}/ssl ]]; then
	warn "Symlink ${I_BASE}/ssl already exists, this installation will modify target"
elif [[ -e ${I_BASE}/ssl ]]; then
	fatal "${I_BASE}/ssl exists and is not a symlink, exiting"
fi

$LN ${OSSL_PREFIX} ${I_BASE}/ssl || fatal "Unable to create symlink ${I_BASE}/ssl"

log "INFO" "Building OpenSSL FIPS module"

${TAR} -xzf ${FIPS}.tar.gz

if [[ ! -d ${FIPS} ]]; then
	fatal "Extraction of ${FIPS} failed"
fi

cd ${WORKDIR}/${FIPS} || fatal "Unable to cd to ${WORKDIR}/${FIPS}"

./config || {
	error "${WORKDIR}/${FIPS}/config returned error"
	fatal "Exiting"
}

$MAKE || {
	fatal "Error during build of ${FIPS}, exiting"
}

log "INFO" "Build completed, will attempt to install"

if [[ -d ${I_BASE}/ssl/fips-2.0 ]]; then
	fatal "Previous installation of FIPS module found, unable to install"
fi

$MAKE install || {
	error "${MAKE} install encountered an error"
	cleanup_install ${I_BASE}/ssl/fips-2.0
	fatal "Exiting"
}

if [[ ! -d ${I_BASE}/ssl/fips-2.0 ]]; then
	fatal "FIPS module installed at unknown location, check build log"
fi

log "INFO" "Installation of FIPS module complete at ${I_BASE}/ssl/fips-2.0"

export FIPSDIR=${I_BASE}/ssl/fips-2.0

log "INFO" "Building FIPS-capable OpenSSL"

cd ${WORKDIR}

${TAR} -xzf ${OSSL}.tar.gz

if [[ ! -d ${OSSL} ]]; then
	fatal "Extraction of ${OSSL} failed"
fi

cd ${WORKDIR}/${OSSL} || fatal "Unable to cd to ${WORKDIR}/${OSSL}"

${OSSL_CONFIG} || fatal "Encountered error running ${OSSL_CONFIG}"

$MAKE depend || fatal "Encountered error running ${MAKE} depend"

$MAKE || fatal "Encountered error running $MAKE"

log "INFO" "Build completed, will attempt to install"

# if [[ -d ${OSSL_PREFIX} ]]; then
# 	fatal "Previous installation of ${OSSL} found, unable to install at ${OSSL_PREFIX}"
# fi

$MAKE install || {
	error "Encountered error running ${MAKE} install"
	cleanup_install ${OSSL_PREFIX}
	fatal "Exiting"
}

log "INFO" "Installation of FIPS-capable OpenSSL complete at ${OSSL_PREFIX}"
