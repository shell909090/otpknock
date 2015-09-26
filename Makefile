### Makefile --- 

## Author: shell@xps13
## Version: $Id: Makefile,v 0.0 2015/09/23 07:07:06 shell Exp $
## Keywords: 
## X-URL: 
TARGET=otpknock

all: build

install: otpknock
	install -m 755 -s otpknock $(DESTDIR)/usr/sbin/
	install -m 755 okssh $(DESTDIR)/usr/bin/
	install -m 644 otpknock.ini $(DESTDIR)/etc/

build: ${TARGET}

clean:
	rm -f ${TARGET}
	rm -f oksshc

otpknock: otpknock.go
	go build -o $@ $^ 

run: otpknock
	./otpknock -config otpknock.ini

genotp:
	python -c 'import imp; imp.load_source("okssh", "./okssh"); import okssh; print okssh.calotp("Y3WRZ5A533WCBPLX")'

sendotp:
	python -c 'import imp; imp.load_source("okssh", "./okssh"); import okssh; okssh.send_token("localhost", 37798, okssh.calotp("Y3WRZ5A533WCBPLX"))'

### Makefile ends here
