# Makefile for BlueMix OpenSSL Wrapper for Go

PACKAGES=crypto ssl bio digest rand

all: $(PACKAGES) run_unit_tests

run_unit_tests: 
	# rm -rf .cover
	# mkdir .cover
	for PKG in $(PACKAGES) ; do \
		FULLPKG=github.com/IBM-Bluemix/golang-openssl-wrapper/$$PKG ; \
		go test -v -coverprofile=$$PKG/coverage.txt -covermode=atomic $$FULLPKG ; done
