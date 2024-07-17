-module(acceptor).

-export([init/3,process/2]).

-include_lib("kernel/include/logger.hrl").

-define(SOCK_OPTS,
        [{inet_backend, socket},
         {reuseaddr, true},
         binary,
         {packet, 0},
         {nodelay, true},
         {active, false}]).

init(Port, Pass, Method) ->
    {ok, Sock} = gen_tcp:listen(Port, ?SOCK_OPTS),
    loop(Sock, cipher:init(Method, Pass)).

loop(Listen, Ctx) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    Pid = spawn(?MODULE, process, [Ctx, Sock]),
    ok = gen_tcp:controlling_process(Sock, Pid),
    loop(Listen, Ctx).

process(Ctx, Client) ->
    {ok, Data} = gen_tcp:recv(Client, 0),
    {Output, Rest, Ctx1} = cipher:decrypt(Ctx, Data),
    {Addr, Port, Text} = common:parse_address(list_to_binary(Output)),
    case gen_tcp:connect(Addr, Port, ?SOCK_OPTS, timer:seconds(2)) of
        {ok, Remote} ->
            ?LOG_DEBUG("succeed: ~s",[Addr]),
            gen_tcp:send(Remote, Text),
            common:relay(Ctx1, Client, Rest, Ctx, Remote);
        {error, Reason} ->
            ?LOG_DEBUG("failed: ~s, error: ~w", [Addr, Reason])
    end.
