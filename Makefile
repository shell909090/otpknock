### Makefile --- 

## Author: shell@xps13
## Version: $Id: Makefile,v 0.0 2015/09/23 07:07:06 shell Exp $
## Keywords: 
## X-URL: 
TARGET=otpknock

build: ${TARGET}

clean:
	rm -f ${TARGET}
	rm -f oksshc

otpknock: main.go
	go build -o $@ $^ 

run: otpknock
	./otpknock -config otpknock.ini

genotp:
	python -c 'import imp; imp.load_source("okssh", "./okssh"); import okssh; print okssh.calotp("Y3WRZ5A533WCBPLX")'

sendotp:
	python -c 'import imp; imp.load_source("okssh", "./okssh"); import okssh; okssh.send_token("localhost", 37798, okssh.calotp("Y3WRZ5A533WCBPLX"))'

### Makefile ends here
