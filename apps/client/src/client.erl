-module(client).

-export([init/5,process/4]).

-include_lib("common/include/common.hrl").

init(Method, Password, LocalPort, RemoteAddr, RemotePort) ->
    Init = cipher:init(Method, Password),
    {ok, Listen} = gen_tcp:listen(LocalPort, ?SOCK_OPTS),
    {ok, {IP, Port}} = inet:sockname(Listen),
    ?LOG_INFO("listening on ~s:~w", [inet:ntoa(IP), Port]),
    {ok, RemoteIP} = inet:getaddr(RemoteAddr, inet),
    loop(Listen, Init, RemoteIP, RemotePort).

loop(ListenSock, Init, RemoteIP, RemotePort) ->
    {ok, Client} = gen_tcp:accept(ListenSock),
    Pid = spawn(?MODULE, process, [Client, Init, RemoteIP, RemotePort]),
    gen_tcp:controlling_process(Client, Pid),
    loop(ListenSock, Init, RemoteIP, RemotePort).

process(Client, Init, RemoteIP, RemotePort) ->
    {ok, <<5, N:8, _:N/binary>>} = gen_tcp:recv(Client, 0),         % ignore method selection
    ok = gen_tcp:send(Client, <<5, 0>>),                            % no authentication required
    {ok, <<5, 1, 0, Dst/binary>>} = gen_tcp:recv(Client, 0),        % CONNECT only
    ok = gen_tcp:send(Client, <<5, 0, 0, Dst/binary>>),             % always succeeded, use DST.ADDR
    {Addr, _, <<>>} = common:parse_address(Dst),
    ?LOG_DEBUG("connecting to: ~s", [common:address_to_string(Addr)]),
    {ok, Request} = gen_tcp:recv(Client, 0),                        % first request
    case gen_tcp:connect(RemoteIP, RemotePort, ?SOCK_OPTS, ?DIAL_TIMEOUT) of
        {ok, Remote} ->
            {Packet, EncState} = cipher:encrypt(Init, <<Dst/binary, Request/binary>>),
            ok = gen_tcp:send(Remote, Packet),
            common:relay(Init, Remote, EncState, Client);
        {error, Reason} ->
            ?LOG_ERROR("remote unreachable: ~p", [Reason])
    end.
