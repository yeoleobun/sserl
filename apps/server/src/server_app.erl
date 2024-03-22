%%%-------------------------------------------------------------------
%% @doc server public API
%% @end
%%%-------------------------------------------------------------------

-module(server_app).

-behaviour(application).
-include_lib("kernel/include/logger.hrl").

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    case maps:from_list(application:get_all_env()) of
        #{port := Port,password := Password,method := Method} ->
            ?LOG_DEBUG(#{port => Port, password => Password, method => Method}),
            server_sup:start_link(Port,Password,Method);
        #{} ->
            {error,"illegal config"}
    end.

stop(_State) ->
    ok.

%% internal functions
