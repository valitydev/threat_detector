-module(td_detection).

-behaviour(gen_server).

-include("threat_detector.hrl").

-export([start_link/2]).
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-export([add_correlator/2]).
-export([process_event/3]).

-record(state, {
    rule :: rule(),
    correlators :: #{pid() => boolean()}
}).

-type state() :: #state{}.

-spec start_link(atom(), rule()) -> gen_server:start_ret().
start_link(RegName, Rule) ->
    gen_server:start_link({local, RegName}, ?MODULE, Rule, []).

-spec add_correlator(atom(), pid()) -> ok.
add_correlator(RegName, Correlator) ->
    gen_server:call(RegName, {add_correlator, Correlator}).

-spec process_event(pid(), event(), term()) -> ok.
process_event(Pid, Event, Selection) ->
    gen_server:cast(Pid, {process_event, Event, Selection}).

-spec init(rule()) -> {ok, state()}.
init(#{detection := Detection} = Rule) ->
    ok = do_subscribe(Detection),
    {ok, #state{rule = Rule, correlators = #{}}}.

-spec handle_call(term(), gen_server:from(), state()) ->
    {reply, term(), state()} | {noreply, state()}.
handle_call({add_correlator, Pid}, _From, #state{correlators = Correlators} = State) ->
    {reply, ok, State#state{correlators = Correlators#{Pid => true}}};
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported_request}, State}.

-spec handle_cast(term(), state()) ->
    {noreply, state()}.
handle_cast({process_event, Event, _Selection}, #state{rule = Rule, correlators = Correlators} = State) ->
    Name = maps:get(name, Rule),
    ok = notify_correlators(Name, Event, Correlators),
    {noreply, State};
handle_cast(_Request, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) ->
    {noreply, state()}.
handle_info({process_event, Event, _Selection}, #state{rule = Rule, correlators = Correlators} = State) ->
    Name = maps:get(name, Rule),
    ok = notify_correlators(Name, Event, Correlators),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, _State) ->
    ok.

-spec code_change(term(), state(), term()) ->
    {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%

%% multiselection and complex conditions not supported yet
%% condition must point to a single selection
do_subscribe(#{condition := SelectionName} = Detection) ->
    Selection = maps:get(SelectionName, Detection),
    %% supported selection by fields only (keywords not supported)
    ok = td_selection:subscribe({self(), SelectionName}, Selection).

notify_correlators(Name, Event, Correlators) ->
    _ = maps:foreach(
        fun(Pid, _) ->
            ok = td_correlation:process_event(Pid, {Name, Event})
        end,
        Correlators
    ),
    ok.
