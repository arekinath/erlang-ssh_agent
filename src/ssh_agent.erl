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

-include_lib("public_key/include/public_key.hrl").

-export([open/1, open/0, close/1]).
-export([list_identities/1, sign/3]).
-export([list_extensions/1, ecdh/3]).

-export_type([client/0, config/0]).

-opaque client() :: pid().

-type config() :: #{path => string()}.
%% Configuration for ssh_agent:open/1. If <code>path</code> is not given,
%% defaults to using the contents of the <code>SSH_AUTH_SOCK</code>
%% environment variable.

-type identity() :: #{
    pubkey => pubkey(),
    comment => binary(),
    fingerprints => [binary()]
    }. %%
%% Information about an "identity" kept in the ssh-agent.
%%
%% This includes the public key itself, the "key comment" (if any), as well as
%% a list of key "fingerprints". The "fingerprints" list includes the SHA256
%% and MD5 fingerprints in OpenSSH style (e.g. <code>SHA256:base64</code> and
%% <code>01:02:ab:cd:...</code>) as binary strings.

-type siginfo() :: #{hash => crypto:hash_algorithm(), signature => binary()}.
%% Signature and associated hash algorithm, as signed by the agent.
%%
%% Signatures are converted to the same format produced by crypto:sign() and
%% expected by crypto:verify() (i.e. X509 ASN.1 format).

-type extension() :: binary().
%% Extension name, in the form specified in <code>draft-miller-ssh-agent</code>
%% (e.g. <code>extension@domain.com</code>).

-type pubkey() :: public_key:public_key().
%% A public key belonging to a key stored in the agent.

%% @doc Opens a new agent connection.
%%
%% The connection is supervised internally within the <code>ssh_agent</code>
%% application. If you want it to disconnect and stop associated processes,
%% you will need to call ssh_agent:close().
-spec open() -> {ok, client()} | {error, term()}.
open() ->
    open(#{}).

%% @doc Opens a new agent connection with explicit configuration.
-spec open(config()) -> {ok, client()} | {error, term()}.
open(Config) ->
    ssh_agent_sup:start_child(Config).

%% @doc Closes a connection to an ssh-agent created by ssh_agent:open().
-spec close(client()) -> ok | {error, term()}.
close(Client) ->
    gen_server:call(Client, close).

%% @doc Gets a list of all identities (key pairs) stored in the agent.
-spec list_identities(client()) -> {ok, [identity()]} | {error, term()}.
list_identities(Client) ->
    gen_server:call(Client, list_keys).

%% @doc Signs binary data using a key stored in the agent.
%%
%% The ssh-agent itself always has the final say regarding which hash algorithm
%% will be used for signing. The algorithm used will be returned along with
%% the signature data.
-spec sign(client(), pubkey(), binary()) -> {ok, siginfo()} | {error, term()}.
sign(Client, #'RSAPublicKey'{} = PubKey, Data) ->
    % RSA is a special case, since we default to sending the RSA_SHA256 flag. If
    % this agent doesn't support RSA-SHA256, it will respond with a "failure"
    % message and we should retry without the flag.
    case gen_server:call(Client, {sign, PubKey, Data}) of
        {error, agent_failure} ->
            gen_server:call(Client, {sign, PubKey, Data, []});
        Res ->
            Res
    end;
sign(Client, PubKey, Data) ->
    gen_server:call(Client, {sign, PubKey, Data}).

%% @doc Lists protocol extensions supported by the agent, if any.
%%
%% If extensions are not supported, this may return an error rather than
%% an empty list.
-spec list_extensions(client()) -> {ok, [extension()]} | {error, term()}.
list_extensions(Client) ->
    gen_server:call(Client, list_extensions).

%% @doc Computes a shared secret using ECDH with a private key in the agent.
%%
%% This is an extension command and may not be supported by the agent.
-spec ecdh(client(), pubkey(), public_key:public_key()) -> {ok, binary()} | {error, term()}.
ecdh(Client, PubKey, OtherKey) ->
    gen_server:call(Client, {ecdh, PubKey, OtherKey}).
