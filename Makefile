.DEFAULT: all

all: dns.json

dns.json: builddns.pl keys/*.pem
	perl builddns.pl > dns.json

