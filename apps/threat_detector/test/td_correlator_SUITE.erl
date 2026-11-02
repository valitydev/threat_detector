-module(td_correlator_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).

-export([
    start_valid_config/1,
    start_fails_on_cycle/1,
    start_fails_on_duplicate_name/1,
    threshold_activates_threat/1,
    below_threshold_stays_open/1,
    non_matching_event_ignored/1,
    event_without_group_field_ignored/1,
    independent_groups/1,
    extra_events_after_activation_ignored/1,
    window_expires_open_instance/1,
    window_not_restarted_by_next_events/1,
    cooldown_deactivates_threat/1,
    cancel_threat_removes_active/1,
    cancel_threat_unknown_group_noop/1,
    cancel_threat_on_open_instance_noop/1,
    condition_gt/1,
    condition_lte/1,
    condition_eq/1,
    condition_neq/1,
    multi_field_grouping/1,
    only_matching_detection_feeds_correlator/1,
    restore_active_threats_after_restart/1
]).

-define(SUBJ, <<"subject.id">>).
-define(STARTUP_FAILURE_TESTS, [start_fails_on_cycle, start_fails_on_duplicate_name]).
-define(SETTLE_MS, 300).

-spec all() -> [atom()].
all() ->
    [
        start_valid_config,
        start_fails_on_cycle,
        start_fails_on_duplicate_name,
        threshold_activates_threat,
        below_threshold_stays_open,
        non_matching_event_ignored,
        event_without_group_field_ignored,
        independent_groups,
        extra_events_after_activation_ignored,
        window_expires_open_instance,
        window_not_restarted_by_next_events,
        cooldown_deactivates_threat,
        cancel_threat_removes_active,
        cancel_threat_unknown_group_noop,
        cancel_threat_on_open_instance_noop,
        condition_gt,
        condition_lte,
        condition_eq,
        condition_neq,
        multi_field_grouping,
        only_matching_detection_feeds_correlator,
        restore_active_threats_after_restart
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    ok = td_ct:init_suite(),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> ok.
end_per_suite(_Config) ->
    ok = td_ct:end_suite().

-spec init_per_testcase(atom(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(TestCase, Config) ->
    Config1 = td_ct:setup_testcase(TestCase, Config),
    case lists:member(TestCase, ?STARTUP_FAILURE_TESTS) of
        true ->
            Config1;
        false ->
            {ok, _} = application:ensure_all_started(threat_detector),
            Config1
    end.

-spec end_per_testcase(atom(), ct_suite:ct_config()) -> ok.
end_per_testcase(_TestCase, _Config) ->
    ok = td_ct:teardown_testcase().

%%% Startup

-spec start_valid_config(ct_suite:ct_config()) -> ok.
start_valid_config(_Config) ->
    Names = [
        search_request,
        unauthorized,
        c_gte3,
        c_gt3,
        c_lte2,
        c_eq2,
        c_neq0,
        c_window,
        c_cooldown,
        c_token
    ],
    lists:foreach(
        fun(Name) -> ?assert(is_pid(whereis(Name)), {not_registered, Name}) end,
        Names
    ),
    ?assert(is_pid(whereis(td_selection))).

-spec start_fails_on_cycle(ct_suite:ct_config()) -> ok.
start_fails_on_cycle(_Config) ->
    ?assertMatch({error, _}, application:ensure_all_started(threat_detector)),
    ?assertEqual(undefined, whereis(td_selection)).

-spec start_fails_on_duplicate_name(ct_suite:ct_config()) -> ok.
start_fails_on_duplicate_name(_Config) ->
    ?assertMatch({error, _}, application:ensure_all_started(threat_detector)),
    ?assertEqual(undefined, whereis(td_selection)).

%%% Event -> detection -> correlation -> threat state

-spec threshold_activates_threat(ct_suite:ct_config()) -> ok.
threshold_activates_threat(_Config) ->
    Key = key(<<"user1">>),
    produce(search_event(<<"user1">>), 3),
    await_threat(c_gte3, Key, #{status => active, aggregate => 3}).

-spec below_threshold_stays_open(ct_suite:ct_config()) -> ok.
below_threshold_stays_open(_Config) ->
    Key = key(<<"user1">>),
    produce(search_event(<<"user1">>), 2),
    await_threat(c_gte3, Key, #{status => open, aggregate => 2}),
    timer:sleep(?SETTLE_MS),
    ?assertEqual(#{status => open, aggregate => 2}, td_correlation:get_threat(c_gte3, Key)).

-spec non_matching_event_ignored(ct_suite:ct_config()) -> ok.
non_matching_event_ignored(_Config) ->
    Event = (search_event(<<"user1">>))#{<<"operation.id">> => <<"other">>},
    produce(Event, 5),
    timer:sleep(?SETTLE_MS),
    ?assertEqual(#{}, td_correlation:get_all_threats(c_gte3)).

-spec event_without_group_field_ignored(ct_suite:ct_config()) -> ok.
event_without_group_field_ignored(_Config) ->
    Event = maps:remove(?SUBJ, search_event(<<"user1">>)),
    produce(Event, 5),
    timer:sleep(?SETTLE_MS),
    ?assertEqual(#{}, td_correlation:get_all_threats(c_gte3)),
    ?assert(is_pid(whereis(c_gte3))).

-spec independent_groups(ct_suite:ct_config()) -> ok.
independent_groups(_Config) ->
    produce(search_event(<<"user1">>), 3),
    produce(search_event(<<"user2">>), 2),
    await_threat(c_gte3, key(<<"user1">>), #{status => active, aggregate => 3}),
    await_threat(c_gte3, key(<<"user2">>), #{status => open, aggregate => 2}),
    ?assertEqual(2, maps:size(td_correlation:get_all_threats(c_gte3))).

-spec extra_events_after_activation_ignored(ct_suite:ct_config()) -> ok.
extra_events_after_activation_ignored(_Config) ->
    Key = key(<<"user1">>),
    produce(search_event(<<"user1">>), 3),
    await_threat(c_gte3, Key, #{status => active, aggregate => 3}),
    produce(search_event(<<"user1">>), 2),
    timer:sleep(?SETTLE_MS),
    ?assertEqual(#{status => active, aggregate => 3}, td_correlation:get_threat(c_gte3, Key)).

%%% Sliding window (c_window: gte 3 within 1s)

-spec window_expires_open_instance(ct_suite:ct_config()) -> ok.
window_expires_open_instance(_Config) ->
    Key = key(<<"user1">>),
    produce(search_event(<<"user1">>), 2),
    await_threat(c_window, Key, #{status => open, aggregate => 2}),
    await_threat(c_window, Key, undefined).

-spec window_not_restarted_by_next_events(ct_suite:ct_config()) -> ok.
window_not_restarted_by_next_events(_Config) ->
    Key = key(<<"user1">>),
    produce(search_event(<<"user1">>), 1),
    await_threat(c_window, Key, #{status => open, aggregate => 1}),
    timer:sleep(400),
    produce(search_event(<<"user1">>), 1),
    await_threat(c_window, Key, #{status => open, aggregate => 2}),
    %% ~1.2s since the first event: window (1s) is closed, a restarted timer would still be alive
    timer:sleep(800),
    ?assertEqual(undefined, td_correlation:get_threat(c_window, Key)).

%%% Cooldown (c_cooldown: gte 2, tag cooldown.2s)

-spec cooldown_deactivates_threat(ct_suite:ct_config()) -> ok.
cooldown_deactivates_threat(_Config) ->
    Key = key(<<"user1">>),
    produce(search_event(<<"user1">>), 2),
    await_threat(c_cooldown, Key, #{status => active, aggregate => 2}),
    await_threat(c_cooldown, Key, undefined, 4000).

-spec cancel_threat_removes_active(ct_suite:ct_config()) -> ok.
cancel_threat_removes_active(_Config) ->
    Key = key(<<"user1">>),
    produce(search_event(<<"user1">>), 2),
    await_threat(c_cooldown, Key, #{status => active, aggregate => 2}),
    ok = td_correlation:cancel_threat(c_cooldown, Key),
    await_threat(c_cooldown, Key, undefined, 1000),
    %% the cooldown timer must have been cancelled: nothing breaks after it would have fired
    timer:sleep(2500),
    ?assert(is_pid(whereis(c_cooldown))),
    ?assertEqual(undefined, td_correlation:get_threat(c_cooldown, Key)),
    %% the group starts from scratch afterwards
    produce(search_event(<<"user1">>), 2),
    await_threat(c_cooldown, Key, #{status => active, aggregate => 2}).

-spec cancel_threat_unknown_group_noop(ct_suite:ct_config()) -> ok.
cancel_threat_unknown_group_noop(_Config) ->
    ok = td_correlation:cancel_threat(c_cooldown, key(<<"nobody">>)),
    timer:sleep(?SETTLE_MS),
    ?assert(is_pid(whereis(c_cooldown))),
    ?assertEqual(#{}, td_correlation:get_all_threats(c_cooldown)).

-spec cancel_threat_on_open_instance_noop(ct_suite:ct_config()) -> ok.
cancel_threat_on_open_instance_noop(_Config) ->
    Key = key(<<"user1">>),
    produce(search_event(<<"user1">>), 1),
    await_threat(c_cooldown, Key, #{status => open, aggregate => 1}),
    ok = td_correlation:cancel_threat(c_cooldown, Key),
    timer:sleep(?SETTLE_MS),
    ?assertEqual(#{status => open, aggregate => 1}, td_correlation:get_threat(c_cooldown, Key)).

%%% Condition operators

-spec condition_gt(ct_suite:ct_config()) -> ok.
condition_gt(_Config) ->
    Key = key(<<"user1">>),
    produce(search_event(<<"user1">>), 3),
    await_threat(c_gt3, Key, #{status => open, aggregate => 3}),
    produce(search_event(<<"user1">>), 1),
    await_threat(c_gt3, Key, #{status => active, aggregate => 4}).

-spec condition_lte(ct_suite:ct_config()) -> ok.
condition_lte(_Config) ->
    Key = key(<<"user1">>),
    produce(search_event(<<"user1">>), 1),
    await_threat(c_lte2, Key, #{status => active, aggregate => 1}).

-spec condition_eq(ct_suite:ct_config()) -> ok.
condition_eq(_Config) ->
    Key = key(<<"user1">>),
    produce(search_event(<<"user1">>), 1),
    await_threat(c_eq2, Key, #{status => open, aggregate => 1}),
    produce(search_event(<<"user1">>), 1),
    await_threat(c_eq2, Key, #{status => active, aggregate => 2}),
    produce(search_event(<<"user1">>), 1),
    timer:sleep(?SETTLE_MS),
    ?assertEqual(#{status => active, aggregate => 2}, td_correlation:get_threat(c_eq2, Key)).

-spec condition_neq(ct_suite:ct_config()) -> ok.
condition_neq(_Config) ->
    Key = key(<<"user1">>),
    produce(search_event(<<"user1">>), 1),
    await_threat(c_neq0, Key, #{status => active, aggregate => 1}).

%%% Multi-field grouping and several detection rules

-spec multi_field_grouping(ct_suite:ct_config()) -> ok.
multi_field_grouping(_Config) ->
    Same = unauthorized_event(<<"u1">>, <<"bearer">>, <<"sig1">>),
    Other = unauthorized_event(<<"u1">>, <<"bearer">>, <<"sig2">>),
    KeySame = token_key(<<"u1">>, <<"bearer">>, <<"sig1">>),
    KeyOther = token_key(<<"u1">>, <<"bearer">>, <<"sig2">>),
    produce(Same, 3),
    produce(Other, 2),
    await_threat(c_token, KeySame, #{status => active, aggregate => 3}),
    await_threat(c_token, KeyOther, #{status => open, aggregate => 2}),
    ?assertEqual(2, maps:size(td_correlation:get_all_threats(c_token))).

-spec only_matching_detection_feeds_correlator(ct_suite:ct_config()) -> ok.
only_matching_detection_feeds_correlator(_Config) ->
    %% authorization.result=allow matches search_request, but not unauthorized
    Allowed = (unauthorized_event(<<"u1">>, <<"bearer">>, <<"sig1">>))#{
        <<"authorization.result">> => <<"allow">>
    },
    produce(Allowed, 3),
    await_threat(c_gte3, key(<<"u1">>), #{status => active, aggregate => 3}),
    timer:sleep(?SETTLE_MS),
    ?assertEqual(#{}, td_correlation:get_all_threats(c_token)),
    %% deny events match both detections
    produce(unauthorized_event(<<"u2">>, <<"bearer">>, <<"sig9">>), 3),
    await_threat(c_token, token_key(<<"u2">>, <<"bearer">>, <<"sig9">>), #{status => active, aggregate => 3}),
    await_threat(c_gte3, key(<<"u2">>), #{status => active, aggregate => 3}).

%%% Restore after restart (c_gte3 has no cooldown tag, so expires_at is NULL)

-spec restore_active_threats_after_restart(ct_suite:ct_config()) -> ok.
restore_active_threats_after_restart(_Config) ->
    Rule = <<"c_gte3">>,
    Pool = default_pool,
    Keys = restore_keys(),
    ok = td_ct:clear_threats(Pool, Rule),
    try
        lists:foreach(fun(Key) -> ok = td_ct:insert_threat(Pool, Rule, Key) end, Keys),
        ok = application:stop(threat_detector),
        {ok, _} = application:ensure_all_started(threat_detector),
        Active = #{status => active, aggregate => undefined},
        %% every key must be restored exactly: same field order, same value types
        lists:foreach(fun(Key) -> await_threat(c_gte3, Key, Active) end, Keys),
        ?assertEqual(lists:sort(Keys), lists:sort(maps:keys(td_correlation:get_all_threats(c_gte3)))),
        %% the restored key must produce the same hash, so cancel_threat deletes the DB row
        [CancelKey | Rest] = Keys,
        ok = td_correlation:cancel_threat(c_gte3, CancelKey),
        await_threat(c_gte3, CancelKey, undefined, 1000),
        ?assertEqual(0, td_ct:count_threats(Pool, Rule, CancelKey)),
        lists:foreach(fun(Key) -> ?assertEqual(1, td_ct:count_threats(Pool, Rule, Key)) end, Rest)
    after
        _ = td_ct:clear_threats(Pool, Rule)
    end.

%%% Helpers (wrappers over td_ct)

%% Group-by field names are binaries, values may be binary, integer, float or boolean
restore_keys() ->
    [
        [{<<"f.bin">>, <<"abc">>}, {<<"f.int">>, 42}, {<<"f.float">>, 1.5}, {<<"f.bool">>, true}],
        %% the same fields in another order form a different group
        [{<<"f.bool">>, true}, {<<"f.float">>, 1.5}, {<<"f.int">>, 42}, {<<"f.bin">>, <<"abc">>}],
        [{<<"f.int">>, -7}],
        %% float with a zero fraction must not turn into an integer
        [{<<"f.float">>, 3.0}],
        [{<<"f.bool">>, false}, {<<"f.bin">>, <<>>}]
    ].

search_event(S) -> td_ct:search_event(S).
unauthorized_event(S, A, B) -> td_ct:unauthorized_event(S, A, B).
key(S) -> td_ct:key(S).
token_key(S, A, B) -> td_ct:token_key(S, A, B).
produce(E, C) -> td_ct:produce(E, C).
await_threat(R, K, E) -> td_ct:await_threat(R, K, E).
await_threat(R, K, E, T) -> td_ct:await_threat(R, K, E, T).
