%%%-------------------------------------------------------------------
%% @doc client public API
%% @end
%%%-------------------------------------------------------------------

-module(client_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    case maps:from_list(application:get_all_env()) of
        #{method := Method,
          password := Password,
          local_port := LocalPort,
          address := RemoteAddr,
          port := RemotePort} ->
            client_sup:start_link(Method, Password, LocalPort, RemoteAddr, RemotePort);
        #{} ->
            {error, "illegal config"}
    end.

stop(_State) ->
    ok.

