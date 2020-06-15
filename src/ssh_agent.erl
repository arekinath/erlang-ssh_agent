%%
%% ssh_agent
%% ssh agent client
%%
%% Copyright 2020 The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(ssh_agent).

-export([open/1, open/0, close/1]).
-export([list_keys/1, sign/3]).
-export([list_extensions/1, ecdh/3]).

-export_type([client/0, config/0]).

-opaque client() :: pid().

-type config() :: #{path => string()}.
-type identity() :: #{
    pubkey => pubkey(),
    comment => binary(),
    fingerprints => [binary()]
    }.
-type siginfo() :: #{hash => crypto:hash_algorithm(), signature => binary()}.
-type extension() :: binary().
-type pubkey() :: public_key:public_key().

-spec open(config()) -> {ok, client()} | {error, term()}.
open(Config) ->
    ssh_agent_sup:start_child(Config).

-spec open() -> {ok, client()} | {error, term()}.
open() ->
    open(#{}).

-spec close(client()) -> ok | {error, term()}.
close(Client) ->
    gen_server:call(Client, close).

-spec list_keys(client()) -> {ok, [identity()]} | {error, term()}.
list_keys(Client) ->
    gen_server:call(Client, list_keys).

-spec sign(client(), pubkey(), binary()) -> {ok, siginfo()} | {error, term()}.
sign(Client, PubKey, Data) ->
    gen_server:call(Client, {sign, PubKey, Data}).

-spec list_extensions(client()) -> {ok, [extension()]} | {error, term()}.
list_extensions(Client) ->
    gen_server:call(Client, list_extensions).

-spec ecdh(client(), pubkey(), public_key:public_key()) -> {ok, binary()} | {error, term()}.
ecdh(Client, PubKey, OtherKey) ->
    gen_server:call(Client, {ecdh, PubKey, OtherKey}).
