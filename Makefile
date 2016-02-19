.PHONY: deps test

all: deps compile

compile:
	./rebar3 compile

clean:
	./rebar3 clean

DIALYZER_APPS = kernel stdlib erts sasl ssl crypto public_key

include tools.mk
