-module(pbkdf2_eqc).

%% Compile C code and compare C code execution with Erlang code.

-export([prop_equivalent/0]).

-include_lib("eqc/include/eqc.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(QC_OUT(P),
	eqc:on_output(fun(Str, Args) -> io:format(user, Str, Args) end, P)).

eqc_test_() ->
    {timeout, 30,
     [
      {timeout, 30, ?_assertEqual(true, eqc:quickcheck(eqc:testing_time(14, ?QC_OUT(prop_equivalent()))))}
     ]
    }.

prop_equivalent() ->
    ?SETUP(fun() ->
                   ok = compile_c_code(),
                   fun(_) -> ok end
           end,
           ?FORALL({Password, Salt, Iterations, KeySize}, {gen_print_bin(), gen_salt(), gen_iterations(), gen_keysize()},
                   begin
                       Port = open_port({spawn, "./pbkdf2-port"}, [{packet, 4}]),
                       Hash = sha, %% only hash openssl supports for PBKDF2 is SHA1 :(
                       {ok, Bin} = pbkdf2:pbkdf2(Hash, Password, Salt, Iterations, KeySize),
                       Result = pbkdf2:to_hex(Bin),
                       port_command(Port, term_to_binary({Hash, Password, Salt, Iterations, KeySize})),
                       Expected = receive
                                      {Port, {data, E}} ->
                                          list_to_binary(E)
                                  after
                                      5000 ->
                                          timeout
                                  end,
                       port_close(Port),
                       ?WHENFAIL(begin
                                     io:format(user, "Password ~p~n", [Password]),
                                     io:format(user, "Salt ~p~n", [Salt]),
                                     io:format(user, "Iterations ~p~n", [Iterations]),
                                     io:format(user, "KeySize ~p~n", [KeySize]),
                                     io:format(user, "Expected ~p~n", [Expected]),
                                     io:format(user, "Result   ~p~n", [Result])
                                 end,
                                 Expected == Result)
                   end)).

compile_c_code() ->
    %% try to compile the openssl port we need to compare the erlang version against:
    case code:lib_dir(erl_interface) of
        {error, Reason} ->
            {error, Reason};
        EIDir ->
            %% EIDir is the erl_interface dir which contains lib and include for erl_interface C code
            PortSrcDir = "./eqc",
            %% yeeehaw
            case os:cmd("gcc -Wno-format -Wno-pointer-sign  -Wno-implicit-function-declaration "++PortSrcDir++"/pbkdf2-port.c -o pbkdf2-port -I"++EIDir++"/include -L"++EIDir++"/lib -lei -lssl -lcrypto") of
                [] ->
                    ok;
                Error ->
                    %% We need access to include files like openssl/evp.h
                    {error, {compiling_c_code, Error}}
            end
    end.

gen_print_str() ->
    ?LET(Xs, list(char()), [X || X <- Xs, io_lib:printable_list([X]), X /= $~, X < 255]).

gen_print_bin() ->
    ?SUCHTHAT(B, ?LET(Xs, gen_print_str(), list_to_binary(Xs)), B/= <<>>).

gen_salt() ->
    ?SUCHTHAT(S, binary(), S /= <<>>).

gen_keysize() ->
    ?LET(Xs, nat(), Xs+5).

gen_iterations() ->
    ?LET(X, ?SUCHTHAT(I, nat(), I > 0), X*X).
