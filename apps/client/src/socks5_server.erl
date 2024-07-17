-module(socks5_server).

-export([init/5, process/4]).

-include_lib("kernel/include/logger.hrl").

-define(SOCK_OPTS,
        [{inet_backend, socket},
         {reuseaddr, true},
         binary,
         {packet, 0},
         {nodelay, true},
         {active, false}]).

init(Method, Password, LocalPort, RemoteAddr, RemotePort) ->
    Ctx = cipher:init(Method, Password),
    {ok, Listen} = gen_tcp:listen(LocalPort, ?SOCK_OPTS),
    loop(Listen, Ctx, RemoteAddr, RemotePort).

loop(ListenSock, Ctx, RemoteAddr, RemotePort) ->
    {ok, Client} = gen_tcp:accept(ListenSock),
    Pid = spawn(?MODULE, process, [Client, Ctx, RemoteAddr, RemotePort]),
    gen_tcp:controlling_process(Client, Pid),
    loop(ListenSock, Ctx, RemoteAddr, RemotePort).

process(Client, Ctx, RemoteAddr, RemotePort) ->
    {ok, <<5, N:8, _:N/binary>>} = gen_tcp:recv(Client, 0),  % ignore method selection
    ok = gen_tcp:send(Client, <<5, 0>>),                     % no authentication required
    {ok, <<5, 1, 0, Dst/binary>>} = gen_tcp:recv(Client, 0), % CONNECT only
    ok = gen_tcp:send(Client, <<5, 0, 0, Dst/binary>>),      % always succeeded, use DST.ADDR
    {Addr, _Port, <<>>} = common:parse_address(Dst),
    ?LOG_DEBUG("connecting: ~s", [Addr]),
    {ok, Payload} = gen_tcp:recv(Client, 0),
    case gen_tcp:connect(RemoteAddr, RemotePort, ?SOCK_OPTS, timer:seconds(3)) of
        {ok, Remote} ->
            {Packet, State} = cipher:encrypt(Ctx, <<Dst/binary, Payload/binary>>),
            ok = gen_tcp:send(Remote, Packet),
            common:relay(Ctx, Remote, State, Client);
        {error, Reason} ->
            ?LOG_DEBUG("remote unreachable, reason: ~w", [Reason])
    end.
