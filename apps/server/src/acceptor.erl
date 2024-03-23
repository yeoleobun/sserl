-module(acceptor).

-export([start/3]).

-include_lib("kernel/include/logger.hrl").

-define(SOCK_OPTS,
        [{inet_backend, socket},
         {reuseaddr, true},
         binary,
         {packet, 0},
         {nodelay, true},
         {active, false}]).

-spec start(Port, Pass, Method) -> no_return()
    when Port :: inet:port_number(),
         Pass :: string(),
         Method :: cipher:ciphers().
start(Port, Pass, Method) ->
    {ok, Sock} = gen_tcp:listen(Port, ?SOCK_OPTS),
    accept(Sock, cipher:init(Method, Pass)).

-spec accept(Sock, State) -> no_return()
    when Sock :: gen_tcp:socket(),
         State :: cipher:state().
accept(Listen, Init) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    Pid = spawn(fun() -> handshake(Init, Sock) end),
    ok = gen_tcp:controlling_process(Sock, Pid),
    accept(Listen, Init).

-spec handshake(Init, Client) -> Result
    when Init :: cipher:state(),
         Client :: inet:socket(),
         Result :: ok.
handshake(Init, Client) ->
    {ok, Data} = gen_tcp:recv(Client, 0),
    {Output, Rest, State} = cipher:decrypt(Init, Data),
    {Addr, Port, Text} = common:parse_address(list_to_binary(Output)),
    case gen_tcp:connect(Addr, Port, ?SOCK_OPTS, timer:seconds(2)) of
        {ok, Remote} ->
            ?LOG_DEBUG(#{addr => Addr, port => Port}),
            gen_tcp:send(Remote, Text),
            common:relay(State, Client, Rest, Init, Remote);
        {error, Reason} ->
            ?LOG_DEBUG("unreacheable: ~s, error: ~w~n", [Addr, Reason])
    end.
