%%%-------------------------------------------------------------------
%% @doc client top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(client_sup).

-behaviour(supervisor).

-export([start_link/5]).

-export([init/1]).

-define(SERVER, ?MODULE).

start_link(Method, Password, LocalPort, RemoteAddr, RemotePort) ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, [Method, Password, LocalPort, RemoteAddr, RemotePort]).

%% sup_flags() = #{strategy => strategy(),         % optional
%%                 intensity => non_neg_integer(), % optional
%%                 period => pos_integer()}        % optional
%% child_spec() = #{id => child_id(),       % mandatory
%%                  start => mfargs(),      % mandatory
%%                  restart => restart(),   % optional
%%                  shutdown => shutdown(), % optional
%%                  type => worker(),       % optional
%%                  modules => modules()}   % optional
init(Args) ->
    SupFlags =
        #{strategy => one_for_one,
          intensity => 1,
          period => 5},
    ChildSpecs =
        [#{id => acceptor,
           start => {socks5_server, start, Args},
           shutdown => brutal_kill}],
    {ok, {SupFlags, ChildSpecs}}.
%% internal functions
