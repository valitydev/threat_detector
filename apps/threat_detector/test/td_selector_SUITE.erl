-module(td_selector_SUITE).

-include_lib("eunit/include/eunit.hrl").

%% API
-export([
    init_per_testcase/2,
    end_per_testcase/2,
    all/0
]).

-export([subscription_base_test/1]).

-spec test() -> _.

-spec all() -> _.
all() ->
    [
        subscription_base_test
    ].

-spec init_per_testcase(_, _) -> _.
init_per_testcase(_TestCase, C) ->
    {ok, Pid} = td_selection:start_link(),
    [{selector, Pid} | C].

-spec end_per_testcase(_, _) -> _.
end_per_testcase(_TestCase, C) ->
    Pid = proplists:get_value(selector, C),
    erlang:exit(Pid, normal),
    ok.

%% Tests
-spec subscription_base_test(_) -> _.
subscription_base_test(_C) ->
    Event1 = #{
        <<"key1">> => <<"value11">>,
        <<"key2">> => <<"value12">>,
        <<"key3">> => <<"value13">>,
        <<"key4">> => <<"value14">>
    },
    Event2 = #{
        <<"key1">> => <<"value21">>,
        <<"key2">> => <<"value22">>,
        <<"key3">> => <<"value23">>
    },
    Event3 = #{
        <<"key1">> => <<"value31">>,
        <<"key2">> => <<"value32">>,
        <<"key3">> => <<"value33">>
    },
    %% subscription for Event1
    SubscriptionParams1 = #{
        <<"key1">> => [
            <<"value1">>,
            <<"value11">>,
            <<"value111">>
        ],
        <<"key2">> => [<<"value12">>],
        <<"key3">> => [<<"value13">>]
    },
    %% subscription for Event2
    SubscriptionParams2 = #{
        <<"key3">> => [<<"value23">>]
    },
    %% subscription for no one
    SubscriptionParams3 = #{
        <<"key1">> => [<<"value11">>],
        <<"key2">> => [<<"value22">>]
    },
    ok = td_selection:subscribe({self(), selection1}, SubscriptionParams1),
    ok = td_selection:subscribe({self(), selection2}, SubscriptionParams2),
    ok = td_selection:subscribe({self(), selection3}, SubscriptionParams3),

    Self = self(),

    ?assertEqual([{Self, selection1}], td_selection:select_subscriptions(Event1)),
    ?assertEqual([{Self, selection2}], td_selection:select_subscriptions(Event2)),
    ?assertEqual([], td_selection:select_subscriptions(Event3)),

    ok = td_selection:produce(Event1),
    ?assertEqual(
        {process_event, Event1, selection1},
        await_msg()
    ),
    ok = td_selection:produce(Event2),
    ?assertEqual(
        {process_event, Event2, selection2},
        await_msg()
    ),
    ok = td_selection:produce(Event3),
    ?assertEqual(
        {error, timeout},
        await_msg()
    ),
    ok.

%

await_msg() ->
    receive
        {'$gen_cast', Msg} ->
            Msg
    after 1000 ->
        {error, timeout}
    end.
