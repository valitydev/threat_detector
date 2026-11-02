-module(td_engine_SUITE).

-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).

-export([
    get_threats_returns_active/1,
    get_threats_excludes_expired_cooldown/1,
    get_threats_not_modified_after_restart/1,
    clear_threats_deactivates_all/1
]).

-spec all() -> _.
all() ->
    [
        get_threats_returns_active,
        get_threats_excludes_expired_cooldown,
        get_threats_not_modified_after_restart,
        clear_threats_deactivates_all
    ].

-spec init_per_suite(_) -> _.
init_per_suite(Config) ->
    ok = td_ct:init_suite(),
    Config.

-spec end_per_suite(_) -> _.
end_per_suite(_Config) ->
    ok = td_ct:end_suite().

-spec init_per_testcase(_, _) -> _.
init_per_testcase(TestCase, Config) ->
    Config1 = td_ct:setup_testcase(TestCase, Config),
    {ok, _} = application:ensure_all_started(threat_detector),
    Config1.

-spec end_per_testcase(_, _) -> _.
end_per_testcase(_TestCase, _Config) ->
    ok = td_ct:teardown_testcase().

%%% Tests (rules: see td_ct:rules_for/1; c_gte3 has no tags and no cooldown,
%%% c_cooldown has the cooldown.2s tag and listens to export events)
-spec get_threats_returns_active(_) -> _.
get_threats_returns_active(_Config) ->
    SubjectId = <<"api_subj_1">>,
    Key = td_ct:key(SubjectId),
    td_ct:produce(td_ct:search_event(SubjectId), 3),
    td_ct:await_threat(c_gte3, Key, #{status => active, aggregate => 3}),
    %% no tags key for a rule without tags
    ?assertEqual(
        {ok, [
            #{
                rule => <<"c_gte3">>,
                level => <<"high">>,
                details => [#{<<"subject.id">> => SubjectId}]
            }
        ]},
        threat_detector:get_threats(SubjectId)
    ),
    %% another subject has no threats
    ?assertEqual({ok, []}, threat_detector:get_threats(<<"api_subj_unknown">>)).

-spec get_threats_excludes_expired_cooldown(_) -> _.
get_threats_excludes_expired_cooldown(_Config) ->
    SubjectId = <<"api_subj_2">>,
    Key = td_ct:key(SubjectId),
    td_ct:produce(td_ct:export_event(SubjectId), 2),
    td_ct:await_threat(c_cooldown, Key, #{status => active, aggregate => 2}),
    {ok, [Threat]} = threat_detector:get_threats(SubjectId),
    ?assertEqual(<<"c_cooldown">>, maps:get(rule, Threat)),
    ?assertEqual([<<"cooldown.2s">>], maps:get(tags, Threat)),
    %% the cooldown (2s) fires: the instance and its DB row are removed
    td_ct:await_threat(c_cooldown, Key, undefined, 4000),
    ?assertEqual({ok, []}, threat_detector:get_threats(SubjectId)).

-spec get_threats_not_modified_after_restart(_) -> _.
get_threats_not_modified_after_restart(_Config) ->
    SubjectId = <<"api_subj_3">>,
    Key = td_ct:key(SubjectId),
    td_ct:produce(td_ct:search_event(SubjectId), 3),
    td_ct:await_threat(c_gte3, Key, #{status => active, aggregate => 3}),
    {ok, [_] = Before} = threat_detector:get_threats(SubjectId),
    ok = application:stop(threat_detector),
    {ok, _} = application:ensure_all_started(threat_detector),
    td_ct:await_threat(c_gte3, Key, #{status => active, aggregate => undefined}),
    ?assertEqual({ok, Before}, threat_detector:get_threats(SubjectId)).

-spec clear_threats_deactivates_all(_) -> _.
clear_threats_deactivates_all(_Config) ->
    SubjectId = <<"api_subj_4">>,
    OtherId = <<"api_subj_5">>,
    Key = td_ct:key(SubjectId),
    OtherKey = td_ct:key(OtherId),
    td_ct:produce(td_ct:search_event(SubjectId), 3),
    td_ct:produce(td_ct:search_event(OtherId), 3),
    td_ct:await_threat(c_gte3, Key, #{status => active, aggregate => 3}),
    td_ct:await_threat(c_gte3, OtherKey, #{status => active, aggregate => 3}),
    ok = threat_detector:clear_threats(SubjectId),
    %% the correlator deletes the DB row before it drops the instance
    td_ct:await_threat(c_gte3, Key, undefined, 1000),
    ?assertEqual({ok, []}, threat_detector:get_threats(SubjectId)),
    %% threats of other subjects are untouched
    ?assertMatch({ok, [#{rule := <<"c_gte3">>}]}, threat_detector:get_threats(OtherId)),
    ?assertEqual(#{status => active, aggregate => 3}, td_correlation:get_threat(c_gte3, OtherKey)).
