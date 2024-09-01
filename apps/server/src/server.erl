-module(server).

-export([init/3, process/2]).

-include_lib("common/include/common.hrl").

init(Port, Pass, Method) ->
    {ok, Sock} = gen_tcp:listen(Port, lists:append(?SOCK_OPTS, [{backlog, 127}])),
    loop(Sock, cipher:init(Method, Pass)).

loop(Listen, Init) ->
    {ok, Sock} = gen_tcp:accept(Listen),
    Pid = spawn(?MODULE, process, [Init, Sock]),
    ok = gen_tcp:controlling_process(Sock, Pid),
    loop(Listen, Init).

process(Init, Client) ->
    {ok, Data} = gen_tcp:recv(Client, 0),
    {Output, DecState} = cipher:decrypt(Init, Data),
    {Addr, Port, Text} = common:parse_address(list_to_binary(Output)),
    Host = common:address_to_string(Addr),
    case gen_tcp:connect(Addr, Port, ?SOCK_OPTS, ?DIAL_TIMEOUT) of
        {ok, Remote} ->
            ?LOG_DEBUG("connected: ~s", [Host]),
            gen_tcp:send(Remote, Text),
            common:relay(DecState, Client, Init, Remote);
        {error, Reason} ->
            ?LOG_DEBUG("connect failed: ~s, error: ~w", [Host, Reason])
    end.
