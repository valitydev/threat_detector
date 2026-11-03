-module(td_selection).

-behaviour(gen_server).

-export([start_link/0]).
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-export([
    subscribe/2,
    produce/1,
    select_subscriptions/1
]).

-type subscription_ref() :: {Subscriber :: pid(), SubscriptionID :: term()}.

-type field_name() :: binary().
-type field_value() :: binary().

-type subscription_params() :: #{
    field_name() => [field_value()]
}.

-type event() :: #{
    field_name() => field_value()
}.

-type state() :: map().
-export_type([subscription_ref/0]).

%% set {subscription_ref, subscription_params}
-define(SUBSCRIPTIONS_TAB, '__regsub_subscription__').
%% bag {{field_name, field_value}, subscription_ref} (secondary index)
-define(SUBSCRIPTIONS_INDEX_TAB, '__regsub_subscription_index__').

%%% API

-spec subscribe(subscription_ref(), subscription_params()) -> ok.
subscribe(SubRef, SubParams) ->
    gen_server:call(?MODULE, {register_subscription, SubRef, SubParams}).

-spec produce(event()) -> ok.
produce(Event) ->
    Subscriptions = gen_server:call(?MODULE, {select_subscriptions, Event}),
    lists:foreach(
        fun({Subscriber, SubscriptionRef}) ->
            %Subscriber ! {process_event, Event, SubscriptionRef}
            ok = td_detection:process_event(Subscriber, Event, SubscriptionRef)
        end,
        Subscriptions
    ).

-spec select_subscriptions(event()) -> [subscription_ref()].
select_subscriptions(Event) ->
    gen_server:call(?MODULE, {select_subscriptions, Event}).

%%
-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec init([]) -> {ok, state()}.
init(_Args) ->
    _ = ets:new(?SUBSCRIPTIONS_INDEX_TAB, [named_table, bag]),
    _ = ets:new(?SUBSCRIPTIONS_TAB, [named_table]),
    {ok, #{}}.

-spec handle_call(term(), gen_server:from(), state()) ->
    {reply, term(), state()} | {noreply, state()}.
handle_call({register_subscription, SubRef, SubParams}, _From, State) ->
    ok = do_register_subscription(SubRef, SubParams),
    %% TODO: maybe monitor subscriber processes
    {reply, ok, State};
handle_call({select_subscriptions, Event}, _From, State) ->
    Subscriptions = do_select_subscriptions(Event),
    {reply, Subscriptions, State};
handle_call(Msg, _From, State) ->
    io:format(user, "WTF CALL: ~p~n", [Msg]),
    {reply, ok, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Request, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, _State) ->
    ok.

-spec code_change(term(), state(), term()) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%

do_register_subscription(SubRef, SubParams) ->
    true = ets:insert(?SUBSCRIPTIONS_TAB, {SubRef, SubParams}),
    maps:fold(
        fun(Field, Values, _Acc) ->
            lists:foreach(
                fun(Value) ->
                    true = ets:insert(?SUBSCRIPTIONS_INDEX_TAB, {{Field, Value}, SubRef})
                end,
                Values
            )
        end,
        ok,
        SubParams
    ).

do_select_subscriptions(Event) ->
    Candidates = select_candidates(Event),
    filter_candidates(Event, Candidates).

select_candidates(Event) ->
    Set = maps:fold(
        fun(Field, Value, Acc) ->
            case ets:lookup_element(?SUBSCRIPTIONS_INDEX_TAB, {Field, Value}, 2, []) of
                [] ->
                    Acc;
                SubRefs ->
                    sets:union(sets:from_list(SubRefs), Acc)
            end
        end,
        sets:new(),
        Event
    ),
    sets:to_list(Set).

filter_candidates(Event, Candidates) ->
    lists:foldl(
        fun(SubRef, Acc) ->
            SubParams = ets:lookup_element(?SUBSCRIPTIONS_TAB, SubRef, 2),
            case match_subscription_params(Event, maps:to_list(SubParams)) of
                true ->
                    [SubRef | Acc];
                false ->
                    Acc
            end
        end,
        [],
        Candidates
    ).

match_subscription_params(Event, SubParams) ->
    match_subscription_params(Event, SubParams, false).

match_subscription_params(_Event, [], Result) ->
    Result;
match_subscription_params(Event, [{ExpectedField, _ExpectedValues} | _Rest], _Result) when
    not is_map_key(ExpectedField, Event)
->
    false;
match_subscription_params(Event, [{ExpectedField, ExpectedValues} | Rest], _Result) ->
    Value = maps:get(ExpectedField, Event),
    case lists:member(Value, ExpectedValues) of
        true ->
            match_subscription_params(Event, Rest, true);
        false ->
            false
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-spec subscription_match_true_test() -> _.
subscription_match_true_test() ->
    SubscriptionParams = #{
        <<"k1">> => [<<"v11">>, <<"v12">>, <<"v13">>],
        <<"k2">> => [<<"v21">>]
    },
    Event = #{
        <<"k1">> => <<"v13">>,
        <<"k2">> => <<"v21">>,
        <<"k3">> => <<"v33">>
    },
    %% Expected logic:
    %% (Event.k1 == SubscriptionParams.k1.1
    %% OR Event.k1 == SubscriptionParams.k1.2
    %% OR Event.k1 == SubscriptionParams.k1.3)
    %% AND
    %% (Event.k2 == SubscriptionParams.k2.1)
    %%
    %% keys that are not included in the SubscriptionParams are ignored (k3 ignored)
    %%
    %% otherwise, it can be expressed through an analogy in SQL
    %% SELECT * FROM events WHERE k1 IN (v11, v12, v13) AND k2 IN (v21)
    ?assertEqual(true, match_subscription_params(Event, maps:to_list(SubscriptionParams))).

-spec subscription_match_false_test() -> _.
subscription_match_false_test() ->
    SubscriptionParams = #{
        <<"k1">> => [<<"v11">>, <<"v12">>, <<"v13">>],
        <<"k3">> => [<<"v21">>]
    },
    Event = #{
        <<"k1">> => <<"v13">>,
        <<"k2">> => <<"v21">>,
        <<"k3">> => <<"v33">>
    },
    ?assertEqual(false, match_subscription_params(Event, maps:to_list(SubscriptionParams))).

-endif.
