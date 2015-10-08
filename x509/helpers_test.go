package x509_test

import (
	"fmt"
	"io/ioutil"
	"path"
	"strings"
)

var (
	CERTDIR   = "testcerts"
	CERTFILES = make(map[string]string)
	CERTS     = make(map[string]string)
)

func init() {
	dfs, e := ioutil.ReadDir(CERTDIR)
	if e != nil {
		fmt.Printf("Failed to read CERTDIR: %s (%s)\n", CERTDIR, e)
		return
	}

	for _, f := range dfs {
		// Skip directories
		if f.IsDir() {
			continue
		}

		fp := path.Join(CERTDIR, f.Name())
		file, e := ioutil.ReadFile(fp)
		// Print and ignore errors
		if e != nil {
			fmt.Printf("Failed to read file in CERTDIR: %s (%s)\n", fp, e)
			continue
		}

		certname := strings.Split(f.Name(), ".")[0]
		CERTFILES[certname] = fp
		CERTS[certname] = string(file)
	}
}
