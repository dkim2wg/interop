SOURCEFILES=$(wildcard *.mkd)
BASENAMES=$(basename $(SOURCEFILES))
XMLFILES=$(addsuffix .xml,$(BASENAMES))
HTMLFILES=$(addsuffix .html,$(BASENAMES))
TXTFILES=$(addsuffix .txt,$(BASENAMES))
GENERATED=$(XMLFILES) $(HTMLFILES) $(TXTFILES)

.PHONY: all clean

all: $(GENERATED)

%.xml:	%.mkd
	kramdown-rfc2629 $< > $@

%.html %.txt:	%.xml
	xml2rfc --html $<
	xml2rfc --text $<

clean:
	rm -f $(GENERATED)
