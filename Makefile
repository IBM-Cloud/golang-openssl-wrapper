# Makefile for BlueMix OpenSSL Wrapper for Go

PACKAGES=crypto ssl bio digest rand

all: $(PACKAGES) run_unit_tests

run_unit_tests: 
	for PKG in $(PACKAGES) ; do \
		echo $$PKG ; \
		cd $$PKG ; \
		go test -v -coverprofile=coverage.txt -covermode=atomic . ; \
		cd .. ; done
