-module(td_correlation).
-behaviour(gen_server).

-include("threat_detector.hrl").

%% API
-export([start_link/2]).
-export([add_correlator/2]).
-export([process_event/2]).
-export([cancel_threat/2]).
-export([grouping_key_from_details/1]).

%% For testing
-export([
    get_threat/2,
    get_all_threats/1
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {
    rule :: rule(),
    type :: binary(),
    %% for cascading processing (not supported yet)
    correlators :: map(),
    cooldown_timeout :: non_neg_integer() | undefined,
    %% rule instances grouped by the values of target fields
    instances :: instances(),
    window_timers :: map(),
    cooldown_timers :: map()
}).

-type state() :: #state{}.

-type instance() :: #{
    %% open - events detected, conditions not met, monitoring over a sliding window
    %% active - condition met, threat active, new events are ignored
    %%   (should be passed along the cascade, not supported yet)
    status := open | active,
    %% current state of the aggregation function for rule instance
    aggregate := term()
}.

-type instance_id() :: [{FieldName :: binary(), FieldValue :: term()}].

-type instances() :: #{
    instance_id() => instance()
}.

-define(DEFAULT_INSTANCE, #{status => open, aggregate => 0}).
-define(DEFAULT_DB_POOL, default_pool).

%%% API

-spec start_link(atom(), rule()) -> gen_server:start_ret().
start_link(RegName, Rule) ->
    gen_server:start_link({local, RegName}, ?MODULE, Rule, []).

-spec add_correlator(atom(), pid()) -> ok.
add_correlator(RegName, Correlator) ->
    gen_server:call(RegName, {add_correlator, Correlator}).

-spec process_event(pid(), {FromRule :: binary(), event()}) -> ok.
process_event(Pid, {FromRule, Event}) ->
    gen_server:cast(Pid, {process_event, {FromRule, Event}}).

-spec cancel_threat(atom(), [{binary(), term()}]) -> ok.
cancel_threat(RegName, GroupingKey) ->
    gen_server:cast(RegName, {cancel_threat, GroupingKey}).

-spec get_threat(atom(), [{binary(), term()}]) -> instance() | undefined.
get_threat(RegName, GroupingKey) ->
    gen_server:call(RegName, {get_threat, GroupingKey}).

-spec get_all_threats(atom()) -> instances().
get_all_threats(RegName) ->
    gen_server:call(RegName, get_all_threats).

%%% gen_server callbacks

-spec init(rule()) -> {ok, state()}.
init(#{correlation := Correlation} = Rule) ->
    ok = connect_inputs(Correlation),
    Tags = maps:get(tags, Rule, []),
    State = #state{
        rule = Rule,
        type = maps:get(type, Correlation),
        correlators = #{},
        cooldown_timeout = cooldown_timeout(Tags),
        instances = #{},
        window_timers = #{},
        cooldown_timers = #{}
    },
    {ok, restore_from_db(maps:get(name, Rule), State)}.

-spec handle_call(term(), gen_server:from(), state()) ->
    {reply, term(), state()} | {noreply, state()}.
handle_call({add_correlator, Pid}, _From, #state{correlators = Correlators} = State) ->
    {reply, ok, State#state{correlators = Correlators#{Pid => true}}};
handle_call({get_threat, GroupingKey}, _From, #state{instances = Instances} = State) ->
    {reply, maps:get(GroupingKey, Instances, undefined), State};
handle_call(get_all_threats, _From, #state{instances = Instances} = State) ->
    {reply, Instances, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unsupported_request}, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast({process_event, {_FromRule, Event}}, State) ->
    %% FromRule is needed for field aliases, not supported yet
    #state{rule = #{correlation := Correlation}, instances = Instances} = State,
    GroupByFields = maps:get(group_by, Correlation),
    NewState =
        case grouping_key(Event, GroupByFields) of
            undefined ->
                %% All GroupByFields must be present in Event, otherwise it is ignored
                State;
            GroupingKey ->
                %% Start window timer only for 'open' instances (not for 'active')
                ShouldStartTimer =
                    case maps:get(GroupingKey, Instances, ?DEFAULT_INSTANCE) of
                        #{status := open} -> true;
                        _ -> false
                    end,
                NewTimers =
                    case ShouldStartTimer of
                        true ->
                            Timespan = maps:get(timespan, Correlation),
                            maybe_start_timer(Timespan * 1000, GroupingKey, window_timer, State#state.window_timers);
                        false ->
                            State#state.window_timers
                    end,
                process_correlation(Event, GroupingKey, State#state{window_timers = NewTimers})
        end,
    {noreply, NewState};
handle_cast({cancel_threat, GroupingKey}, #state{instances = Instances} = State) ->
    NewState =
        case maps:get(GroupingKey, Instances, #{}) of
            #{status := active} ->
                Name = maps:get(name, State#state.rule),
                logger:info("[audit] Cancel threat ~p for ~p", [Name, GroupingKey]),
                ok = delete_threat(Name, GroupingKey),
                State#state{
                    instances = maps:remove(GroupingKey, Instances),
                    window_timers = maybe_cancel_timer(GroupingKey, State#state.window_timers),
                    cooldown_timers = maybe_cancel_timer(GroupingKey, State#state.cooldown_timers)
                };
            _ ->
                State
        end,
    {noreply, NewState};
handle_cast(_Request, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info({timeout, _TRef, {window_timer, GroupingKey}}, State) ->
    #state{
        rule = #{name := Name},
        window_timers = WindowTimers,
        instances = Instances
    } = State,
    NewWindowTimers = maps:remove(GroupingKey, WindowTimers),
    NewState =
        case maps:find(GroupingKey, Instances) of
            {ok, #{status := active}} ->
                %% Race: instance was activated while timer was in flight
                logger:warning("window timer fired for active threat in rule ~p, key ~p", [Name, GroupingKey]),
                State#state{window_timers = NewWindowTimers};
            {ok, #{status := open}} ->
                %% the sliding window has closed, the condition has not been met:
                %% delete instance
                State#state{
                    instances = maps:remove(GroupingKey, Instances),
                    window_timers = NewWindowTimers
                };
            error ->
                %% Instance was removed (e.g. by cancel_threat or cooldown) before timer fired
                State#state{window_timers = NewWindowTimers}
        end,
    {noreply, NewState};
handle_info({timeout, _TRef, {cooldown_timer, GroupingKey}}, State) ->
    #state{
        rule = #{name := Name},
        cooldown_timers = CooldownTimers,
        instances = Instances
    } = State,
    NewCooldownTimers = maps:remove(GroupingKey, CooldownTimers),
    NewState =
        case maps:find(GroupingKey, Instances) of
            {ok, #{status := active}} ->
                logger:info("[audit] Cancel threat ~p for ~p by timeout", [Name, GroupingKey]),
                ok = delete_threat(Name, GroupingKey),
                %% deactivate threat: delete instance and cancel any remaining window timer
                State#state{
                    instances = maps:remove(GroupingKey, Instances),
                    window_timers = maybe_cancel_timer(GroupingKey, State#state.window_timers),
                    cooldown_timers = NewCooldownTimers
                };
            {ok, #{status := open}} ->
                %% Should not happen: cooldown timer is started only for active threats
                logger:error("cooldown timer fired for open instance in rule ~p, key ~p", [Name, GroupingKey]),
                State#state{cooldown_timers = NewCooldownTimers};
            error ->
                %% Instance was removed (e.g. by cancel_threat) before timer fired
                State#state{cooldown_timers = NewCooldownTimers}
        end,
    {noreply, NewState};
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, _State) ->
    ok.

-spec code_change(term(), state(), term()) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%% Internal functions

maybe_start_timer(undefined, _GroupingKey, _Type, Timers) ->
    Timers;
maybe_start_timer(_TimeoutMs, GroupingKey, _Type, Timers) when is_map_key(GroupingKey, Timers) ->
    Timers;
maybe_start_timer(TimeoutMs, GroupingKey, Type, Timers) ->
    TRef = erlang:start_timer(TimeoutMs, self(), {Type, GroupingKey}),
    Timers#{GroupingKey => TRef}.

maybe_cancel_timer(GroupingKey, Timers) ->
    case maps:take(GroupingKey, Timers) of
        {TRef, NewTimers} ->
            _ = erlang:cancel_timer(TRef),
            NewTimers;
        error ->
            Timers
    end.

process_correlation(_Event, GroupingKey, #state{type = <<"event_count">>} = State) ->
    #state{
        rule = #{correlation := #{condition := #{check_fun := CheckFun}}},
        instances = Instances
    } = State,
    #{status := Status, aggregate := Counter} =
        Instance =
        maps:get(GroupingKey, Instances, ?DEFAULT_INSTANCE),
    case Status of
        open ->
            NewCounter = Counter + 1,
            case CheckFun(NewCounter) of
                true ->
                    activate_threat(GroupingKey, Instance, NewCounter, State);
                false ->
                    NewInstance = Instance#{aggregate => NewCounter},
                    State#state{instances = Instances#{GroupingKey => NewInstance}}
            end;
        active ->
            %% the threat has already been activated
            %% TODO: if a cascade is configured, then propagate the event
            State
    end;
process_correlation(_Event, _GroupingKey, #state{type = Type} = State) ->
    logger:error("unsupported correlation type: ~p", [Type]),
    State.

activate_threat(GroupingKey, Instance, Aggregate, State) ->
    #state{
        rule = Rule,
        cooldown_timeout = Timeout,
        cooldown_timers = CooldownTimers,
        window_timers = WindowTimers,
        instances = Instances
    } = State,
    NewInstance = Instance#{status => active, aggregate => Aggregate},
    RuleName = maps:get(name, Rule),
    Level = maps:get(level, Rule, <<"low">>),
    Tags = maps:get(tags, Rule, []),
    ok = persist_threat(RuleName, Level, GroupingKey, Tags, Timeout),
    logger:info(
        "[audit] Threat detected. Rule: ~p, Level: ~p, Instance: ~p, Tags: ~p",
        [RuleName, Level, GroupingKey, Tags]
    ),
    _ = prometheus_counter:inc(threats_detection_counter, [RuleName]),
    State#state{
        instances = Instances#{GroupingKey => NewInstance},
        window_timers = maybe_cancel_timer(GroupingKey, WindowTimers),
        cooldown_timers = maybe_start_timer(Timeout, GroupingKey, cooldown_timer, CooldownTimers)
    }.

restore_from_db(RuleName, State) ->
    SQL = "SELECT details, expires_at FROM threats WHERE rule = $1",
    case epg_pool:query(db_pool(), SQL, [RuleName]) of
        {ok, _Cols, Rows} ->
            lists:foldl(fun(Row, S) -> restore_row(RuleName, Row, S) end, State, Rows);
        {error, Reason} ->
            logger:error("failed to restore threats for rule ~p: ~p", [RuleName, Reason]),
            State
    end.

restore_row(RuleName, {DetailsJson, ExpiresAt}, State) ->
    GroupingKey = grouping_key_from_details(DetailsJson),
    Instance = #{status => active, aggregate => undefined},
    case ExpiresAt of
        null ->
            %% no cooldown configured: restore instance as-is
            State#state{instances = (State#state.instances)#{GroupingKey => Instance}};
        ExpiresAtDatetime ->
            RemainingMs = remaining_ms(ExpiresAtDatetime),
            case RemainingMs =< 0 of
                true ->
                    %% expired while the process was down: clean up
                    logger:info("[audit] Cancel threat ~p for ~p by timeout", [RuleName, GroupingKey]),
                    ok = delete_threat(RuleName, GroupingKey),
                    State;
                false ->
                    %% still active: restore instance and rearm cooldown timer
                    NewTimers = maybe_start_timer(
                        RemainingMs, GroupingKey, cooldown_timer, State#state.cooldown_timers
                    ),
                    State#state{
                        instances = (State#state.instances)#{GroupingKey => Instance},
                        cooldown_timers = NewTimers
                    }
            end
    end.

-spec grouping_key_from_details(binary()) -> [{binary(), term()}].
grouping_key_from_details(JsonBin) ->
    %% details is stored as [{K => V}] — a list of single-key maps, preserving order
    Decoded = jsx:decode(JsonBin),
    lists:map(
        fun(M) ->
            [{K, V}] = maps:to_list(M),
            {K, V}
        end,
        Decoded
    ).

%% epgsql returns timestamptz as {{Y,M,D},{H,Min,SecFloat}} in UTC
remaining_ms({Date, {H, Min, SecFloat}}) ->
    Datetime = {Date, {H, Min, trunc(SecFloat)}},
    NowSecs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    ExpiresSecs = calendar:datetime_to_gregorian_seconds(Datetime),
    (ExpiresSecs - NowSecs) * 1000.

db_pool() ->
    application:get_env(threat_detector, db_pool, ?DEFAULT_DB_POOL).

delete_threat(RuleName, GroupingKey) ->
    Pool = db_pool(),
    Hash = crypto:hash(sha256, term_to_binary(GroupingKey, [{minor_version, 2}])),
    SQL = "DELETE FROM threats WHERE rule = $1 AND rule_instance_hash = $2",
    case epg_pool:query(Pool, SQL, [RuleName, Hash]) of
        {ok, _} ->
            ok;
        {error, Reason} ->
            io:format(user, "DELETION ERROR ~p~n", [Reason]),
            logger:error("failed to delete threat for rule ~p: ~p", [RuleName, Reason]),
            ok
    end.

persist_threat(RuleName, Level, GroupingKey, Tags, TimeoutMs) ->
    Pool = db_pool(),
    Hash = crypto:hash(sha256, term_to_binary(GroupingKey, [{minor_version, 2}])),
    SubjectId = proplists:get_value(<<"subject.id">>, GroupingKey, <<>>),
    Details = jsx:encode([#{K => V} || {K, V} <- GroupingKey]),
    TagsJson = jsx:encode(Tags),
    ExpiresAt = expires_at(TimeoutMs),
    SQL =
        "INSERT INTO threats "
        "(rule, rule_instance_hash, subject_id, level, details, tags, expires_at) "
        "VALUES ($1, $2, $3, $4::text::threat_level, $5, $6, $7) "
        "ON CONFLICT (rule, rule_instance_hash) DO NOTHING",
    case epg_pool:query(Pool, SQL, [RuleName, Hash, SubjectId, Level, Details, TagsJson, ExpiresAt]) of
        {ok, _} ->
            ok;
        {error, Reason} ->
            logger:error("failed to persist threat for rule ~p: ~p", [RuleName, Reason]),
            ok
    end.

expires_at(undefined) ->
    null;
expires_at(TimeoutMs) ->
    GregorianNow = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    calendar:gregorian_seconds_to_datetime(GregorianNow + TimeoutMs div 1000).

cooldown_timeout([]) ->
    undefined;
cooldown_timeout([<<"cooldown.", Timeout/binary>> = Tag | Rest]) ->
    try td_sigma_parser:parse(timespan, Timeout) of
        Seconds ->
            Seconds * 1000
    catch
        _:_ ->
            logger:error("unexpected cooldown tag: ~p", [Tag]),
            cooldown_timeout(Rest)
    end;
cooldown_timeout([_ | Rest]) ->
    cooldown_timeout(Rest).

grouping_key(Event, GroupByFields) ->
    case lists:all(fun(Field) -> is_map_key(Field, Event) end, GroupByFields) of
        true ->
            [{Field, maps:get(Field, Event)} || Field <- GroupByFields];
        false ->
            undefined
    end.

connect_inputs(#{rules := Inputs}) ->
    lists:foreach(
        fun(Input) ->
            RegName = erlang:binary_to_atom(Input),
            %% In the general case, either a detector or a correlator can serve as an input.
            %% Not supported yet
            ok = gen_server:call(RegName, {add_correlator, self()})
        end,
        Inputs
    ).
