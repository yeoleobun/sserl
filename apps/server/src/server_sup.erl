%%%-------------------------------------------------------------------
%% @doc server top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(server_sup).

-behaviour(supervisor).

-export([start_link/3]).
-export([init/1]).

start_link(Port, Password, Method) ->
    supervisor:start_link(?MODULE, [Port, Password, Method]).

%% sup_flags() = #{strategy => strategy(),         % optional
%%                 intensity => non_neg_integer(), % optional
%%                 period => pos_integer()}        % optional
%% child_spec() = #{id => child_id(),       % mandatory
%%                  start => mfargs(),      % mandatory
%%                  restart => restart(),   % optional
%%                  shutdown => shutdown(), % optional
%%                  type => worker(),       % optional
%%                  modules => modules()}   % optional
init([Port, Password, Method]) ->
    SupFlags =
        #{strategy => one_for_one,
          intensity => 1,
          period => 5},
    ChildSpecs =
        [#{id => acceptor,
           start => {acceptor, start, [Port, Password, Method]},
           shutdown => brutal_kill}],
    {ok, {SupFlags, ChildSpecs}}.

%% internal functions
