%%%-------------------------------------------------------------------
%% @doc tpl public API
%% @end
%%%-------------------------------------------------------------------

-module(threat_detector_app).

-behaviour(application).

-export([start/2, stop/1]).

-spec start(normal, any()) -> {ok, pid()} | {error, any()}.
start(_StartType, _StartArgs) ->
    threat_detector_sup:start_link().

-spec stop(any()) -> ok.
stop(_State) ->
    ok.

%% internal functions
