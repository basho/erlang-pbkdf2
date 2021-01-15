.PHONY: deps test

all: deps compile

compile: deps
	./rebar3 compile

deps:
	test -d deps || ./rebar3 get-deps

clean:
	./rebar3 clean

distclean: clean
	./rebar3 delete-deps

DIALYZER_APPS = kernel stdlib erts sasl ssl crypto public_key

include tools.mk
