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
-define(TIME_OUT, timer:seconds(30)).

-spec start(Port, Pass, Method) -> no_return()
    when Port :: inet:port_number(),
         Pass :: string(),
         Method :: cipher:cipher().
start(Port, Pass, Method) ->
    {ok, Sock} = gen_tcp:listen(Port, ?SOCK_OPTS),
    accept(Sock, cipher:init(Method, Pass)).

-spec accept(Sock, State) -> no_return()
    when Sock :: gen_tcp:socket(),
         State :: cipher:state().
accept(Listen, Init) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    Pid = spawn(fun() -> process(Init, Sock, <<>>) end),
    ok = gen_tcp:controlling_process(Sock, Pid),
    accept(Listen, Init).

-spec process(Init, Client, Buff) -> Result
    when Init :: cipher:state(),
         Client :: inet:socket(),
         Buff :: binary(),
         Result :: ok.
process(Init, Client, Buff) ->
    {ok, Packet} = gen_tcp:recv(Client, 0),
    Data = <<Buff/binary, Packet/binary>>,
    {Output, Rest, State} = cipher:decrypt(Init, Data),
    case parse_address(list_to_binary(Output)) of
        {Addr, Port, Text} ->
            ?LOG_DEBUG(#{addr => Addr, port => Port}),
            {ok, Remote} = gen_tcp:connect(Addr, Port, ?SOCK_OPTS),
            gen_tcp:send(Remote, Text),
            inet:setopts(Client, [{active, once}]),
            inet:setopts(Remote, [{active, once}]),
            relay(State, Client, Rest, Init, Remote);
        continue ->
            process(Init, Client, Data)
    end.

-spec relay(DecState, Client, Buff, EncState, Remote) -> Result
    when DecState :: cipher:state(),
         EncState :: cipher:state(),
         Client :: inet:socket(),
         Remote :: inet:socket(),
         Buff :: binary(),
         Result :: ok.
relay(DecState, Client, Buff, EncState, Remote) ->
    receive
        {tcp, Client, Packet} ->
            {Text, Rest, State} = cipher:decrypt(DecState, <<Buff/binary, Packet/binary>>),
            gen_tcp:send(Remote, Text),
            inet:setopts(Client, [{active, once}]),
            relay(State, Client, Rest, EncState, Remote);
        {tcp, Remote, Packet} ->
            {Output, State} = cipher:encrypt(EncState, Packet),
            gen_tcp:send(Client, Output),
            inet:setopts(Remote, [{active, once}]),
            relay(DecState, Client, Buff, State, Remote);
        {tcp_closed, _} ->
            gen_tcp:close(Client),
            gen_tcp:close(Remote)
    after ?TIME_OUT ->
        gen_tcp:close(Client),
        gen_tcp:close(Remote)
    end.

-spec parse_address(Input) -> Output
    when Input :: binary(),
         Rest :: binary(),
         Addr :: inet:ip_address() | inet:hostname(),
         Port :: inet:port_number(),
         Output :: {Addr, Port, Rest} | continue.
parse_address(<<1, A, B, C, D, Port:16, Rest/binary>>) ->
    {{A, B, C, D}, Port, Rest};
parse_address(<<3, Len, Host:Len/binary, Port:16, Rest/binary>>) ->
    {binary_to_list(Host), Port, Rest};
parse_address(<<4,
                A:16,
                B:16,
                C:16,
                D:16,
                E:16,
                F:16,
                G:16,
                H:16,
                Port:16,
                Rest/binary>>) ->
    {{A, B, C, D, E, F, G, H}, Port, Rest};
parse_address(_) ->
    continue.
