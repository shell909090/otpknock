### Makefile --- 

## Author: shell@xps13
## Version: $Id: Makefile,v 0.0 2015/09/23 07:07:06 shell Exp $
## Keywords: 
## X-URL: 
TARGET=otpknock

all: build

install: otpknock
	install -d $(DESTDIR)/usr/sbin/
	install -m 755 -s otpknock $(DESTDIR)/usr/sbin/
	install -d $(DESTDIR)/usr/bin/
	install -m 755 okssh $(DESTDIR)/usr/bin/
	install -d $(DESTDIR)/etc/
	install -m 600 otpknock.json $(DESTDIR)/etc/

build: ${TARGET}

clean:
	rm -f ${TARGET} oksshc
	rm -rf debuild

clean-deb:
	debian/rules clean

otpknock: otpknock.go
	go build -ldflags "-s" -o $@ $^

build-deb:
	dpkg-buildpackage --no-sign
	mkdir -p debuild
	mv -f ../otpknock_* debuild

dk-build:
	docker run -it --rm -v $$PWD:/srv/ -w /srv/ gobuilder make build-deb
	sudo chown -R shell:shell debuild/

dk-build32:
	docker run -it --rm -v $$PWD:/srv/ -w /srv/ i386/gobuilder make build-deb
	sudo chown -R shell:shell debuild/

run: otpknock
	./otpknock -config otpknock.json

genotp:
	python3 -c '__name__=""; exec(open("okssh").read(), globals()); print(calotp("Y3WRZ5A533WCBPLX"))'

sendotp:
	python3 -c '__name__=""; exec(open("okssh").read(), globals()); send_token("localhost", 37798, calotp("Y3WRZ5A533WCBPLX"))'

### Makefile ends here
