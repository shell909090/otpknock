### Makefile --- 

## Author: shell@xps13
## Version: $Id: Makefile,v 0.0 2015/09/23 07:07:06 shell Exp $
## Keywords: 
## X-URL: 
TARGET=otpknock

build: ${TARGET}

clean:
	rm -f ${TARGET}

otpknock: main.go
	go build -o $@ $^ 

### Makefile ends here
