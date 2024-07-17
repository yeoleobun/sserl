-module(common).
-define(TIMEOUT, timer:seconds(30)).

-export([relay/4, relay/5, parse_address/1]).
-export([address_to_binary/2]).

-spec relay(DecState, DecSock, EncState, EncSock) -> Result
    when DecState :: cipher:state(),
         EncState :: cipher:state(),
         DecSock :: inet:socket(),
         EncSock :: inet:socket(),
         Result :: ok.
relay(DecState, DecSock, EncState, EncSock) ->
    relay(DecState, DecSock, <<>>, EncState, EncSock).

relay(DecState, DecSock, DecBuff, EncState, EncSock) ->
    inet:setopts(DecSock, [{active, once}]),
    inet:setopts(EncSock, [{active, once}]),
    receive
        {tcp, DecSock, Packet} ->
            {Text, Rest, State} = cipher:decrypt(DecState, <<DecBuff/binary, Packet/binary>>),
            gen_tcp:send(EncSock, Text),
            relay(State, DecSock, Rest, EncState, EncSock);
        {tcp, EncSock, Packet} ->
            {Output, State} = cipher:encrypt(EncState, Packet),
            gen_tcp:send(DecSock, Output),
            relay(DecState, DecSock, DecBuff, State, EncSock);
        {tcp_closed, _} ->
            gen_tcp:close(DecSock),
            gen_tcp:close(EncSock)
    after ?TIMEOUT ->
        gen_tcp:close(DecSock),
        gen_tcp:close(EncSock)
    end.

-spec parse_address(Input) -> Output
    when Input :: binary(),
         Rest :: binary(),
         Addr :: inet:ip_address() | inet:hostname(),
         Port :: inet:port_number(),
         Output :: {Addr, Port, Rest}.
parse_address(<<1, A, B, C, D, Port:16, Rest/binary>>) ->
    {{A, B, C, D}, Port, Rest};
parse_address(<<3, Len, Host:Len/binary, Port:16, Rest/binary>>) ->
    {binary_to_list(Host), Port, Rest};
parse_address(<<4,A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16,Port:16,Rest/binary>>) ->
    {{A, B, C, D, E, F, G, H}, Port, Rest}.

-spec address_to_binary(Addr, Port) -> Result
    when Addr :: inet:ip_address() | inet:hostname(),
         Port :: inet:port_number(),
         Result :: binary().
address_to_binary({A, B, C, D}, Port) ->
    <<1, A, B, C, D, Port:16>>;
address_to_binary({A, B, C, D, E, F, G, H}, Port) ->
    <<4, A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16, Port:16>>;
address_to_binary(Host, Port) ->
    Len = length(Host),
    Bin = list_to_binary(Host),
    <<3, Len:16, Bin/binary, Port:16>>.
