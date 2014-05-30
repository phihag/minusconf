#!/usr/bin/make -f

all: dist

test:
	./test_minusconf.py

tar:
	version=$$(sed -n "s/VERSION='\([^']*\)'/\1/p" < minusconf.py) && \
		tar --create --numeric-owner --owner 0 --group 0 --transform "s#^#minusconf-$${version}/#" "--file=minusconf-$${version}.tar" \
			minusconf.py test_minusconf.py LICENSE protocol.txt Makefile && \
		gzip < "minusconf-$${version}.tar" > "minusconf-$${version}.tar.gz" && \
		bzip2 < "minusconf-$${version}.tar" > "minusconf-$${version}.tar.bz2"

clean:
	rm -f *.pyc
	rm -f minusconf*.tar{,.bz2,.gz}

dist: test tar

