% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License. You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
% License for the specific language governing permissions and limitations under
% the License.

-module(pbkdf2_tests).

-include_lib("eunit/include/eunit.hrl").


-define(RFC6070_TEST_VECTORS, [
	{[sha, <<"password">>, <<"salt">>, 1, 20],
			<<"0c60c80f961f0e71f3a9b524af6012062fe037a6">>},
	{[sha, <<"password">>, <<"salt">>, 2, 20],
			<<"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957">>},
	{[sha, <<"password">>, <<"salt">>, 4096, 20],
			<<"4b007901b765489abead49d926f721d065a429c1">>},
	{[sha, <<"passwordPASSWORDpassword">>, <<"saltSALTsaltSALTsaltSALTsaltSALTsalt">>, 4096, 25],
			<<"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038">>},
	{[sha, <<"pass\0word">>, <<"sa\0lt">>, 4096, 16],
			<<"56fa6aa75548099dcc37d7f03425e0c3">>},
	{[sha, <<"password">>, <<"salt">>, 16777216, 20],
			<<"eefe3d61cd4da4e4e9945b3d6ba2158c2634e984">>}
]).


pbkdf2_hex(Args) ->
	io:format("Running test with Args = ~p~n", [Args]),
	{ok, Key} = apply(pbkdf2, pbkdf2, Args),
	pbkdf2:to_hex(Key).


rfc6070_correctness_test_() ->
	[
		{timeout, 120,
			?_assertEqual(
				Expected,
				pbkdf2_hex(Args)
				)
			}
		|| {Args, Expected} <- ?RFC6070_TEST_VECTORS
		].

-define(RFC3962_TEST_VECTORS, [
		{[sha, <<"password">>, <<"ATHENA.MIT.EDUraeburn">>, 1, 16],
			<<"cdedb5281bb2f801565a1122b2563515">>},
		{[sha, <<"password">>, <<"ATHENA.MIT.EDUraeburn">>, 1, 32],
			<<"cdedb5281bb2f801565a1122b2563515"
				"0ad1f7a04bb9f3a333ecc0e2e1f70837">>},
		{[sha, <<"password">>, <<"ATHENA.MIT.EDUraeburn">>, 2, 16],
			<<"01dbee7f4a9e243e988b62c73cda935d">>},
		{[sha, <<"password">>, <<"ATHENA.MIT.EDUraeburn">>, 2, 32],
			<<"01dbee7f4a9e243e988b62c73cda935d"
				"a05378b93244ec8f48a99e61ad799d86">>},
		{[sha, <<"password">>, <<"ATHENA.MIT.EDUraeburn">>, 1200, 16],
			<<"5c08eb61fdf71e4e4ec3cf6ba1f5512b">>},
		{[sha, <<"password">>, <<"ATHENA.MIT.EDUraeburn">>, 1200, 32],
			<<"5c08eb61fdf71e4e4ec3cf6ba1f5512b"
				"a7e52ddbc5e5142f708a31e2e62b1e13">>},
		{[sha, <<"password">>, binary:encode_unsigned(16#1234567878563412), 5, 16],
			<<"d1daa78615f287e6a1c8b120d7062a49">>},
		{[sha, <<"password">>, binary:encode_unsigned(16#1234567878563412), 5, 32],
			<<"d1daa78615f287e6a1c8b120d7062a49"
				"3f98d203e6be49a6adf4fa574b6e64ee">>},
		{[sha, <<"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX">>,
				<<"pass phrase equals block size">>, 1200, 16],
			<<"139c30c0966bc32ba55fdbf212530ac9">>},
		{[sha, <<"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX">>,
				<<"pass phrase equals block size">>, 1200, 32],
			<<"139c30c0966bc32ba55fdbf212530ac9"
				"c5ec59f1a452f5cc9ad940fea0598ed1">>},
		{[sha, <<"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX">>,
				<<"pass phrase exceeds block size">>, 1200, 16],
			<<"9ccad6d468770cd51b10e6a68721be61">>},
		{[sha, <<"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX">>,
				<<"pass phrase exceeds block size">>, 1200, 32],
			<<"9ccad6d468770cd51b10e6a68721be61"
				"1a8b4d282601db3b36be9246915ec82a">>}
]).

rfc3962_correctness_test_() ->
	[
		{timeout, 60,
			?_assertEqual(
				Expected,
				pbkdf2_hex(Args)
				)
			}
		|| {Args, Expected} <- ?RFC3962_TEST_VECTORS
		].

