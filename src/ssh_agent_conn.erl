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

-module(ssh_agent_conn).

-include_lib("public_key/include/public_key.hrl").
-include("SSHSignature.hrl").

-behaviour(gen_server).

-export([start_link/1]).
-export([init/1, terminate/2, handle_call/3, handle_cast/2, handle_info/2]).

-type from() :: {pid(), Tag :: term()}.
-type cmd() :: {from(), op()}.

-spec start_link(ssh_agent:config()) -> {ok, pid()} | {error, term()}.
start_link(Config) ->
    gen_server:start_link(?MODULE, [Config], []).

-record(?MODULE, {
    config :: ssh_agent:config(),
    path :: string(),
    socket :: gen_tcp:socket(),
    cmd = idle :: idle | cmd(),
    cmdq = queue:new() :: queue:queue(cmd()),
    closing = false :: boolean()
    }).

-define(SSH_AGENTC_REQUEST_IDENTITIES, 11).
-define(SSH_AGENTC_SIGN_REQUEST, 13).
-define(SSH_AGENTC_LOCK, 22).
-define(SSH_AGENTC_UNLOCK, 23).
-define(SSH_AGENTC_EXTENSION, 27).

-define(SSH_AGENT_SUCCESS, 6).
-define(SSH_AGENT_FAILURE, 5).
-define(SSH_AGENT_EXT_FAILURE, 28).
-define(SSH_AGENT_IDENTITIES_ANSWER, 12).
-define(SSH_AGENT_SIGN_RESPONSE, 14).

-define(SSH_AGENT_RSA_SHA2_256, 2).
-define(SSH_AGENT_RSA_SHA2_512, 4).

-type sign_flag() :: ?SSH_AGENT_RSA_SHA2_256 | ?SSH_AGENT_RSA_SHA2_512.
-record(sign_request, {
    key :: public_key:public_key(),
    data :: binary(),
    flags = [] :: [sign_flag()]
}).

-record(lock_request, {
    passphrase :: binary()
}).

-record(unlock_request, {
    passphrase :: binary()
}).

-record(extension_request, {
    extension :: binary(),
    data :: term()
}).

-type ecdh_flag() :: none.
-record(ext_ecdh, {
    key :: public_key:public_key(),
    partner :: public_key:public_key(),
    flags = [] :: [ecdh_flag()]
}).

-type op() :: list_keys | #sign_request{} | #lock_request{} |
    #unlock_request{} | #extension_request{}.

init([Config]) ->
    Path = case Config of
        #{path := P} -> P;
        _ ->
            case os:getenv("SSH_AUTH_SOCK") of
                false -> error(no_auth_sock_path);
                P -> P
            end
    end,
    {ok, Socket} = gen_tcp:connect({local, Path}, 0,
        [binary, {packet, 4}, {active, true}]),
    {ok, #?MODULE{path = Path, socket = Socket, config = Config}}.

terminate(_Why, #?MODULE{socket = S}) ->
    gen_tcp:close(S),
    ok.

handle_call(list_keys, From, S0 = #?MODULE{}) ->
    enqueue_and_send({From, request_identities}, S0);

handle_call({sign, Key, Data}, From, S0 = #?MODULE{}) ->
    Flags = case Key of
        #'RSAPublicKey'{} -> [?SSH_AGENT_RSA_SHA2_256];
        _ -> []
    end,
    Req = #sign_request{key = Key, data = Data, flags = Flags},
    enqueue_and_send({From, Req}, S0);

handle_call({sign, Key, Data, Flags}, From, S0 = #?MODULE{}) ->
    Req = #sign_request{key = Key, data = Data, flags = Flags},
    enqueue_and_send({From, Req}, S0);

handle_call({lock, Pw}, From, S0 = #?MODULE{}) ->
    enqueue_and_send({From, #lock_request{passphrase = Pw}}, S0);

handle_call({unlock, Pw}, From, S0 = #?MODULE{}) ->
    enqueue_and_send({From, #unlock_request{passphrase = Pw}}, S0);

handle_call(list_extensions, From, S0 = #?MODULE{}) ->
    Req = #extension_request{extension = <<"query">>},
    enqueue_and_send({From, Req}, S0);

handle_call({ecdh, Key, OtherKey}, From, S0 = #?MODULE{}) ->
    Req = #extension_request{
        extension = <<"ecdh@joyent.com">>,
        data = #ext_ecdh{
            key = Key,
            partner = OtherKey
        }
    },
    enqueue_and_send({From, Req}, S0);

handle_call(close, From, S0 = #?MODULE{}) ->
    gen_server:reply(From, ok),
    {stop, normal, S0}.

enqueue_and_send(FromOp, S0 = #?MODULE{cmdq = Q0}) ->
    Q1 = queue:in(FromOp, Q0),
    S1 = S0#?MODULE{cmdq = Q1},
    case S0 of
        #?MODULE{cmd = idle} -> send_next(S1);
        _ -> {noreply, S1}
    end.

encode_sign_request(#sign_request{key = K, data = D, flags = F}) ->
    KBlob = public_key:ssh_encode(K, ssh2_pubkey),
    Flags = lists:foldl(fun (X, Acc) -> X bor Acc end, 0, F),
    <<?SSH_AGENTC_SIGN_REQUEST,
      (byte_size(KBlob)):32/big, KBlob/binary,
      (byte_size(D)):32/big, D/binary,
      Flags:32/big>>.

encode_lock_request(#lock_request{passphrase = Pw}) ->
    <<?SSH_AGENTC_LOCK,
      (byte_size(Pw)):32/big, Pw/binary>>;
encode_lock_request(#unlock_request{passphrase = Pw}) ->
    <<?SSH_AGENTC_UNLOCK,
      (byte_size(Pw)):32/big, Pw/binary>>.

encode_ext_ecdh(#ext_ecdh{key = K, partner = P, flags = F}) ->
    [] = F,
    KBlob = public_key:ssh_encode(K, ssh2_pubkey),
    PBlob = public_key:ssh_encode(P, ssh2_pubkey),
    <<(byte_size(KBlob)):32/big, KBlob/binary,
      (byte_size(PBlob)):32/big, PBlob/binary,
      0:32/big>>.

encode_ext_request(#extension_request{extension = Ext, data = D}) ->
    Data = case Ext of
        <<"query">> -> <<>>;
        <<"ecdh@joyent.com">> -> encode_ext_ecdh(D)
    end,
    <<?SSH_AGENTC_EXTENSION,
      (byte_size(Ext)):32/big, Ext/binary,
      (byte_size(Data)):32/big, Data/binary>>.

decode_ext_reply_query(<<NExts:32/big, Rem0/binary>>) ->
    {Exts, _Rem1} = lists:foldl(fun
        (_N, {Acc0, <<L0:32/big, Ext:L0/binary, IRem0/binary>>}) ->
            {[Ext | Acc0], IRem0}
    end, {[], Rem0}, lists:seq(1, NExts)),
    {ok, lists:reverse(Exts)}.

decode_ext_reply_ecdh(<<L0:32/big, Secret:(L0)/binary>>) ->
    {ok, Secret}.

decode_success_ext(#extension_request{extension = Ext}, Bin) ->
    case Ext of
        <<"query">> -> decode_ext_reply_query(Bin);
        <<"ecdh@joyent.com">> -> decode_ext_reply_ecdh(Bin)
    end.

decode_failure_ext(_Op, Bin) ->
    {error, Bin}.

to_colonhex(Bin) ->
    Hex = << <<Y>> || <<X:4>> <= Bin,
        Y <- string:to_lower(integer_to_list(X,16)) >>,
    Pairs = [ <<X,Y>> || <<X,Y>> <= Hex ],
    iolist_to_binary(lists:join(<<":">>, Pairs)).

decode_identity(<<L0:32/big, KeyBlob:(L0)/binary,
                  L1:32/big, Comment:(L1)/binary, Rem/binary>>) ->
    case (catch public_key:ssh_decode(KeyBlob, ssh2_pubkey)) of
        {'EXIT', Why} ->
            {error, {bad_identity, Why}};
        PubKey ->
            Fps = [
                iolist_to_binary([
                    "SHA256:", base64:encode(crypto:hash(sha256, KeyBlob))]),
                to_colonhex(crypto:hash(md5, KeyBlob))
            ],
            Id = #{pubkey => PubKey, comment => Comment, fingerprints => Fps},
            {ok, Id, Rem}
    end.

decode_n_identities(0, SoFar, <<>>) -> {ok, lists:reverse(SoFar)};
decode_n_identities(0, _SoFar, _) -> {error, leftover_bytes};
decode_n_identities(N, SoFar, Bin0) ->
    case decode_identity(Bin0) of
        {ok, K, Bin1} ->
            decode_n_identities(N - 1, [K | SoFar], Bin1);
        Err -> Err
    end.

decode_identities_answer(<<NKeys:32/big, Rem/binary>>) ->
    decode_n_identities(NKeys, [], Rem).

decode_sign_response(#sign_request{key = K, flags = _F},
                     <<L0:32/big, Sig:(L0)/binary>>) ->
    <<L1:32/big, SigAlg:(L1)/binary,
      L2:32/big, SigData:(L2)/binary>> = Sig,
    case {K, SigAlg} of
        {#'RSAPublicKey'{}, <<"ssh-rsa">>} ->
            {ok, #{hash => sha, signature => SigData}};
        {#'RSAPublicKey'{}, <<"rsa-sha2-256">>} ->
            {ok, #{hash => sha256, signature => SigData}};
        {#'RSAPublicKey'{}, <<"rsa-sha2-512">>} ->
            {ok, #{hash => sha512, signature => SigData}};
        {{#'ECPoint'{}, _}, <<"ecdsa-sha2-", Curve/binary>>} ->
            H = case Curve of
                <<"nistp256">> -> sha256;
                <<"nistp384">> -> sha384;
                <<"nistp521">> -> sha512
            end,
            <<L3:32/big, R:(L3)/big-unit:8,
              L4:32/big, S:(L4)/big-unit:8>> = SigData,
            {ok, Asn1Sig} = 'SSHSignature':encode('ECDSASignature',
                    #'ECDSASignature'{r = R, s = S}),
            {ok, #{hash => H, signature => Asn1Sig}};
        {{ed_pub, ed25519, _}, <<"ssh-ed25519">>} ->
            {ok, #{hash => none, signature => SigData}};
        _ ->
            {error, {bad_signature_algo, SigAlg}}
    end.

send_next(S0 = #?MODULE{cmdq = Q0, socket = Socket}) ->
    case queue:out(Q0) of
        {{value, {From, Op}}, Q1} ->
            Msg = case Op of
                request_identities -> <<?SSH_AGENTC_REQUEST_IDENTITIES>>;
                #sign_request{} -> encode_sign_request(Op);
                #lock_request{} -> encode_lock_request(Op);
                #unlock_request{} -> encode_lock_request(Op);
                #extension_request{} -> encode_ext_request(Op)
            end,
            ok = gen_tcp:send(Socket, Msg),
            {noreply, S0#?MODULE{cmdq = Q1, cmd = {From, Op}}};
        _ ->
            {noreply, S0#?MODULE{cmd = idle}}
    end.

handle_info({tcp, Socket, Data}, S0 = #?MODULE{socket = Socket}) ->
    #?MODULE{cmd = {From, Op}} = S0,
    case Data of
        <<?SSH_AGENT_SUCCESS>> ->
            gen_server:reply(From, ok),
            send_next(S0);
        <<?SSH_AGENT_SUCCESS, Rem/binary>> ->
            Rep = decode_success_ext(Op, Rem),
            gen_server:reply(From, Rep),
            send_next(S0);
        <<?SSH_AGENT_FAILURE>> ->
            gen_server:reply(From, {error, agent_failure}),
            send_next(S0);
        <<?SSH_AGENT_FAILURE, Rem/binary>> ->
            gen_server:reply(From, {error, {agent_failure, Rem}}),
            send_next(S0);
        <<?SSH_AGENT_EXT_FAILURE>> ->
            gen_server:reply(From, {error, agent_ext_failure}),
            send_next(S0);
        <<?SSH_AGENT_EXT_FAILURE, Rem/binary>> ->
            Rep = decode_failure_ext(Op, Rem),
            gen_server:reply(From, Rep),
            send_next(S0);
        <<?SSH_AGENT_IDENTITIES_ANSWER, Rem/binary>> ->
            Rep = decode_identities_answer(Rem),
            gen_server:reply(From, Rep),
            send_next(S0);
        <<?SSH_AGENT_SIGN_RESPONSE, Rem/binary>> ->
            Rep = decode_sign_response(Op, Rem),
            gen_server:reply(From, Rep),
            send_next(S0);
        <<Code, Rem/binary>> ->
            gen_server:reply(From, {error, {unsupported_response, Code, Rem}}),
            send_next(S0)
    end;

handle_info({tcp_closed, Socket}, S0 = #?MODULE{closing = true, socket = Socket}) ->
    0 = queue:len(S0#?MODULE.cmdq),
    {stop, normal, S0};

handle_info({tcp_closed, Socket}, S0 = #?MODULE{closing = false, socket = Socket}) ->
    lists:foreach(fun ({From, _Op}) ->
        gen_server:reply(From, {error, closed})
    end, queue:to_list(S0#?MODULE.cmdq)),
    {stop, {error, unexpected_close}, S0};

handle_info({tcp_error, Socket, Reason}, S0 = #?MODULE{socket = Socket}) ->
    lists:foreach(fun ({From, _Op}) ->
        gen_server:reply(From, {error, Reason})
    end, queue:to_list(S0#?MODULE.cmdq)),
    {stop, {error, Reason}, S0}.

handle_cast(Req, S0 = #?MODULE{}) ->
    {stop, {unknown_cast, Req}, S0}.
