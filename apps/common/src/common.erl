-module(common).

-include("common.hrl").

-export([relay/4, parse_address/1, address_to_string/1]).

-spec relay(DecState, DecSock, EncState, EncSock) -> Result
    when DecState :: context(),
         EncState :: context(),
         DecSock :: inet:socket(),
         EncSock :: inet:socket(),
         Result :: ok.

relay(DecState, DecSock, EncState, EncSock) ->
    inet:setopts(DecSock, [{active, once}]),
    inet:setopts(EncSock, [{active, once}]),
    receive
        {tcp, DecSock, Packet} ->
            {Text, State} = cipher:decrypt(DecState, Packet),
            gen_tcp:send(EncSock, Text),
            relay(State, DecSock, EncState, EncSock);
        {tcp, EncSock, Packet} ->
            {Output, State} = cipher:encrypt(EncState, Packet),
            gen_tcp:send(DecSock, Output),
            relay(DecState, DecSock, State, EncSock);
        {tcp_closed, _} ->
            break
    after ?RELAY_TIMOUT ->
        break
    end,
    gen_tcp:close(DecSock),
    gen_tcp:close(EncSock).

-spec parse_address(Input) -> Output
    when Input :: binary(),
         Rest :: binary(),
         Addr :: inet:ip_address() | string(),
         Port :: inet:port_number(),
         Output :: {Addr, Port, Rest}.
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
    {{A, B, C, D, E, F, G, H}, Port, Rest}.

-spec address_to_string(Address) -> Output
    when Address :: inet:ip_address() | string(),
         Output :: string().
address_to_string(Addr) ->
    case inet:is_ip_address(Addr) of
        true ->
            inet:ntoa(Addr);
        false ->
            Addr
    end.
