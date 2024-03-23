-module(socks5_server).

-export([start/5]).
-include_lib("kernel/include/logger.hrl").

-define(SOCK_OPTS,
        [{inet_backend, socket},
         {reuseaddr, true},
         binary,
         {packet, 0},
         {nodelay, true},
         {active, false}]).

-spec start(Method, Password, LocalPort, RemoteAddr, RemotePort) -> Result
    when Method :: cipher:ciphers(),
         Password :: string(),
         LocalPort :: inet:port_number(),
         RemoteAddr :: inet:socket_address() | inet:hostname(),
         RemotePort :: inet:port_number(),
         Result :: ok.
start(Method, Password, LocalPort, RemoteAddr, RemotePort) ->
    Init = cipher:init(Method, Password),
    ?LOG_DEBUG("listening on ~w~n",[LocalPort]),
    {ok, Listen} = gen_tcp:listen(LocalPort, ?SOCK_OPTS),
    accept(Listen, Init, RemoteAddr, RemotePort).

-spec accept(ListenSock, Init, RemoteAddr, RemotePort) -> Result
    when ListenSock :: inet:socket(),
         Init :: cipher:state(),
         RemoteAddr :: inet:socket_address() | inet:hostname(),
         RemotePort :: inet:port_number(),
         Result :: no_return().
accept(ListenSock, Init, RemoteAddr, RemotePort) ->
    {ok, Client} = gen_tcp:accept(ListenSock),
    Pid = spawn(fun() -> handshake(Client, Init, RemoteAddr, RemotePort) end),
    gen_tcp:controlling_process(Client, Pid),
    accept(ListenSock, Init, RemoteAddr, RemotePort).

-spec handshake(Client, Init, RemoteAddr, RemotePort) -> Result
    when Client :: inet:socket(),
         Init :: cipher:state(),
         RemoteAddr :: inet:socket_address() | inet:hostname(),
         RemotePort :: inet:port_number(),
         Result :: ok.
handshake(Client, Init, RemoteAddr, RemotePort) ->
    {ok, <<5, N:8, _:N/binary>>} = gen_tcp:recv(Client, 0),  % ignore method selection
    ok = gen_tcp:send(Client, <<5, 0>>),                     % no authentication required
    {ok, <<5, 1, 0, Dst/binary>>} = gen_tcp:recv(Client, 0), % CONNECT only
    ok = gen_tcp:send(Client, <<5, 0, 0, Dst/binary>>),      % always succeeded, use DST.ADDR
    {Addr,Port,<<>>} = common:parse_address(Dst),
    ?LOG_DEBUG(#{addr => Addr,port => Port}),
    {ok, Payload} = gen_tcp:recv(Client, 0),
    {ok, Remote} = gen_tcp:connect(RemoteAddr, RemotePort, ?SOCK_OPTS, timer:seconds(1)),
    {Packet, State} = cipher:encrypt(Init, <<Dst/binary, Payload/binary>>),
    ok = gen_tcp:send(Remote, Packet),
    common:relay(Init, Remote, State, Client).
