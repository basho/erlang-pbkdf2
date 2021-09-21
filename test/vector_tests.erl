%% -------------------------------------------------------------------
%%
%% Copyright (c) 2017 Basho Technologies, Inc.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------

-module(vector_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-type digest()  :: pbkdf2:digest_func_info().
-type gname()   :: atom().
-type group()   :: {gname(), [vector()]}.
-type vector()  :: {
        Digest  :: digest(),
        PW      :: binary(),
        Salt    :: binary(),
        Iters   :: pos_integer(),
        DkLen   :: pos_integer(),
        DK      :: binary()}.

%%
%% A couple of test vectors have iteration counts in the millions, which can
%% take minutes to compute on a fast platform.
%% As a rule of thumb, around 10 seconds per million rounds should provide
%% enough headroom on a decent bare-metal processor devoted to the task.
%% In normal automated build tests, we probably don't want any single vector
%% to take more than a few seconds.
%%
% -define(MAX_ITERS,  (64 * 1024 * 1024)).

-ifndef(MAX_ITERS).
-define(MAX_ITERS,  (64 * 1024)).
-endif.
%% Allow plenty of room for VMs and loaded testbeds.
-define(TIMEOUT,    (?MAX_ITERS div 4000)).

%% ===================================================================
%% Tests
%% ===================================================================

-spec vectors_test_() -> [tuple()].

vectors_test_() ->
    {_, _, Beam} = code:get_object_code(?MODULE),
    TestDir = filename:join(filename:dirname(filename:dirname(Beam)), test),
    VFiles  = filelib:wildcard(filename:join(TestDir, "*-vectors.config")),
    FSets   = [T || {ok, T} <- [file:consult(F) || F <- VFiles, filelib:is_regular(F)]],
    VSets   = lists:append(FSets),
    Tests   = lists:append([gen_group(Elem) || Elem <- VSets]),
    Tests.

%% ===================================================================
%% Internal
%% ===================================================================

-spec gen_group(group()) -> [tuple()].

gen_group({GName, Vectors}) ->
    {Tests, _} = lists:mapfoldl(
        fun(Vector, Index) ->
            {tester(GName, Index, Vector), (Index + 1)}
        end, 1, Vectors),
    Tests.

-spec tester(GName :: gname(), Index :: pos_integer(), Vector :: vector())
            -> [tuple()].

tester(GName, Index, Vector) ->
    Title = lists:flatten(io_lib:format("~s(~b)", [GName, Index])),
    {Title, {timeout, ?TIMEOUT, fun() -> test_vector(Vector) end}}.

-spec test_vector(vector()) -> ok | no_return().

test_vector({_, _, _, Iters, _, _}) when Iters > ?MAX_ITERS ->
    io:put_chars(user, " too many iterations ");

test_vector({Digest, PW, Salt, Iters, DkLen, DK}) ->
    ?assertEqual({ok, DK}, pbkdf2:pbkdf2(Digest, PW, Salt, Iters, DkLen)).

-endif. % ?TEST
