GO = GOPATH="`pwd`" go
VERSION = 1.0
DEBVERSION = 1
prefix = /opt/local
sysconfdir = /etc

all: deps
	$(GO) install gopush_server

deps:
	$(GO) get -d all

install: all
	install -d $(DESTDIR)$(prefix)/gopush/bin
	install -m 554 bin/* $(DESTDIR)$(prefix)/gopush/bin/
	install -m 444 *.html $(DESTDIR)$(prefix)/gopush/
	install -d $(DESTDIR)$(sysconfdir)
	install -m 644 config.json.sample $(DESTDIR)$(sysconfdir)/gopush.json
	if [ "$(INITSCRIPT_TYPE)" != "" ]; then \
		if [ -e init/$(INITSCRIPT_TYPE) ]; then \
			cd init/$(INITSCRIPT_TYPE) && DESTDIR="$(DESTDIR)" sysconfdir="$(sysconfdir)" make install ;\
		fi \
	fi

clean:
	rm -rf bin pkg

debtar:
	mkdir gopush-$(VERSION)
	cp -a src *.html config.json.sample Makefile init gopush-$(VERSION)
	tar czf gopush_$(VERSION).orig.tar.gz gopush-$(VERSION)
	rm -r gopush-$(VERSION)

deb: debtar
	mkdir work
	cd work && \
	mv ../gopush_$(VERSION).orig.tar.gz . && \
	tar xzf gopush_$(VERSION).orig.tar.gz && \
	cd gopush-$(VERSION) && \
	cp -R ../../debian . && \
	GOROOT="$(GOROOT)" PATH="$(PATH)" INITSCRIPT_TYPE="debian" debuild --preserve-envvar=PATH --preserve-envvar=GOROOT --preserve-envvar=INITSCRIPT_TYPE -us -uc -d
	mv work/*.deb .
	rm -r work
