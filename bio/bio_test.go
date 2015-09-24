package bio_test

import (
	. "github.com/ScarletTanager/openssl/bio"

	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"io/ioutil"
	"strings"
)

var _ = Describe("Bio", func() {
	Describe("Basic I/O", func() {
		var (
			b    BIO
			text = "Some really really really really really really really really really really really long test data"
		)

		Context("Using a memory store", func() {
			It("Should create a new bio using memory store", func() {
				b = BIO_new(BIO_s_mem())
				Expect(b).NotTo(BeNil())
			})

			It("Should be writable", func() {
				r := BIO_puts(b, text)
				Expect(r).NotTo(Equal(-2))
			})

			It("Should be readable", func() {
				buf := make([]byte, len(text))
				r := BIO_gets(b, buf, len(text)+1)
				Expect(r).To(Equal(len(text)))
				Expect(string(buf)).To(Equal(text))
			})

			It("Should free the memory store bio", func() {
				Expect(BIO_free(b)).To(Equal(1))
			})
		})

		Context("Using file storage", func() {
			It("Should create a new bio using file storage", func() {
				b = BIO_new(BIO_s_file())
				Expect(b).NotTo(BeNil())
			})

			It("Should free the file storage bio", func() {
				Expect(BIO_free(b)).To(Equal(1))
			})

			It("Should be writable with BIO_printf", func() {
				b = BIO_new(BIO_s_file())
				Expect(BIO_write_filename(b, "biotest.out")).To(Equal(1))
				Expect(BIO_seek(b, 0)).To(BeEquivalentTo(0))
				Expect(BIO_printf(b, text)).To(Equal(len(text)))
				Expect(BIO_free(b)).To(Equal(1))
			})

			It("Should be writable with BIO_write", func() {
				b = BIO_new(BIO_s_file())
				Expect(BIO_write_filename(b, "biotest.out")).To(Equal(1))
				Expect(BIO_seek(b, 0)).To(BeEquivalentTo(0))
				Expect(BIO_write(b, text, len(text))).To(Equal(len(text)))
				Expect(BIO_free(b)).To(Equal(1))
			})

			It("Should be readable with BIO_gets", func() {
				buf := make([]byte, len(text))
				b = BIO_new(BIO_s_file())
				Expect(BIO_read_filename(b, "biotest.out")).To(Equal(1))
				Expect(BIO_seek(b, 0)).To(BeEquivalentTo(0))
				Expect(BIO_gets(b, buf, len(text)+1)).To(Equal(len(text)))
				Expect(string(buf)).To(Equal(text))
				Expect(BIO_free(b)).To(Equal(1))
			})

			It("Should be readable with BIO_read", func() {
				buf := make([]byte, len(text))
				b = BIO_new(BIO_s_file())
				Expect(BIO_read_filename(b, "biotest.out")).To(Equal(1))
				Expect(BIO_seek(b, 0)).To(BeEquivalentTo(0))
				Expect(BIO_read(b, buf, len(text)+1)).To(Equal(len(text)))
				Expect(string(buf)).To(Equal(text))
				Expect(BIO_free(b)).To(Equal(1))
			})
		})

		Context("Using a connection", func() {
			var (
				host    = "www.google.com"
				port    = "http"
				request = strings.Join([]string{
					"HEAD / HTTP/1.1",
					"User-Agent: https://github.com/ScarletTanager/openssl",
					fmt.Sprintf("Host: %s", host),
					"Accept: */*",
				}, "\n")
			)

			It("Should create a new bio using a connection", func() {
				b = BIO_new(BIO_s_connect())
				Expect(b).NotTo(BeNil())
			})

			It("Should set the hostname of the connection", func() {
				Expect(BIO_set_conn_hostname(b, host)).To(BeEquivalentTo(1))
			})

			It("Should return the correct host", func() {
				Expect(BIO_get_conn_hostname(b)).To(Equal(host))
			})

			It("Should set the port of the connection", func() {
				Expect(BIO_set_conn_port(b, port)).To(BeEquivalentTo(1))
			})

			It("Should return the correct port", func() {
				Expect(BIO_get_conn_port(b)).To(Equal(port))
			})

			It("Should connect successfully", func() {
				Expect(BIO_do_connect(b)).To(BeEquivalentTo(1))
			})

			// It("Should reset successfully", func() {
			// 	Expect(BIO_reset(b)).To(Equal(1))
			// })

			// It("Should connect successfully after resetting", func() {
			// 	Expect(BIO_do_connect(b)).To(BeEquivalentTo(1))
			// })

			It("Should execute the request successfully", func() {
				Expect(BIO_write(b, request, len(request))).To(Equal(len(request)))
			})

			// It("Should successfully receive a response", func() {
			// buf := make([]byte, 2048)
			// Expect(BIO_read(b, buf, 2048)).To(Equal(2048))
			// buf := make([]byte, 50)
			// Expect(BIO_read(b, buf, 1024)).To(Equal(1024))
			// Expect(BIO_read(b, buf, 50)).To(Equal(len(buf)))
			// })

			// It("Should reset successfully", func() {
			// 	Expect(BIO_reset(b)).To(Equal(1))
			// })

			It("Should free the connection", func() {
				Expect(BIO_free(b)).To(Equal(1))
			})
		})

		Context("Making a connection", func() {
			It("Connects successfully", func() {
				dest := "www.google.com:http"
				bio := BIO_new_connect(dest)
				Expect(bio).NotTo(BeNil())
				Expect(BIO_do_connect(bio)).To(BeEquivalentTo(1))
				Expect(BIO_free(bio)).To(Equal(1))
			})
		})

		Context("File I/O", func() {
			var filename, text string
			var fbio BIO
			BeforeEach(func() {
				mode := "w+"
				filename = "biotest.out"
				text = "To Kill A Mockingbird"
				fbio = BIO_new_file(filename, mode)
				Expect(fbio).NotTo(BeNil())
			})

			AfterEach(func() {
				/* Assumes only a single BIO in the chain... */
				Expect(BIO_free(fbio)).To(Equal(1))
			})

			It("Writes to the file, reads using native Go I/O", func() {
				Expect(BIO_puts(fbio, text)).To(BeNumerically(">=", 1))
				Expect(BIO_flush(fbio)).To(BeEquivalentTo(1))
				/* For file BIOs, BIO_seek() returns 0 on success */
				Expect(BIO_seek(fbio, 0)).To(BeEquivalentTo(0))
				/* Temp block to check with native go I/O */
				fbuf, _ := ioutil.ReadFile(filename)
				s := string(fbuf[:])
				Expect(s).To(Equal(text))
			})

			It("Writes to the file, reads from the BIO", func() {
				Expect(BIO_puts(fbio, text)).To(BeNumerically(">=", 1))
				Expect(BIO_flush(fbio)).To(BeEquivalentTo(1))
				/* For file BIOs, BIO_seek() returns 0 on success */
				Expect(BIO_seek(fbio, 0)).To(BeEquivalentTo(0))

				rbuf := make([]byte, len(text))
				l := BIO_gets(fbio, rbuf, len(text)+1)
				/* Check that we've read enough bytes */
				Expect(l).To(BeNumerically(">=", len(text)))

				/* Check that the contents are what we wrote */
				s := string(rbuf[:])
				Expect(len(s)).To(Equal(len(text)))
				Expect(s).To(Equal(text))
			})
		})
	})
})
