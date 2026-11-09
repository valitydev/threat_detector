-module(td_server_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("bouncer_proto/include/bouncer_threats_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_ctx_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_ctx_v1_thrift.hrl").

-export([all/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

-export([
    process_event_returns_ok/1,
    get_context_returns_active_threats/1,
    get_context_excludes_expired_cooldown/1,
    get_context_empty_when_no_threats/1,
    clear_context_deactivates_threats/1
]).

-define(SUBJ, <<"subject.id">>).

%%% Common Test callbacks

-spec all() -> [atom()].
all() ->
    [
        process_event_returns_ok,
        get_context_returns_active_threats,
        get_context_excludes_expired_cooldown,
        get_context_empty_when_no_threats,
        clear_context_deactivates_threats
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    %% postgres pool + migrator
    ok = td_ct:init_suite(),
    %% scoper is required by the thrift handler
    {ok, _} = application:ensure_all_started(scoper),
    %% Thrift server on a dedicated test port
    ServerApps = genlib_app:start_application_with(td_server, [
        {ip, "::"},
        {port, 8023},
        {services, #{detector => #{path => <<"/v1/threat_detector">>}}},
        {protocol_opts, #{request_timeout => 10000}},
        {transport_opts, #{max_connections => 1000, num_acceptors => 10}},
        {shutdown_timeout, 0},
        {woody_event_handlers, [woody_event_handler_default]}
    ]),
    [{suite_apps, ServerApps} | Config].

-spec end_per_suite(ct_suite:ct_config()) -> ok.
end_per_suite(Config) ->
    Apps = proplists:get_value(suite_apps, Config, []),
    ok = genlib_app:stop_unload_applications(Apps),
    ok = td_ct:end_suite().

-spec init_per_testcase(atom(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(TestCase, Config) ->
    ok = td_ct:clear_all_threats(),
    Config1 = td_ct:setup_testcase(TestCase, Config),
    {ok, _} = application:ensure_all_started(threat_detector),
    Client = td_thrift_client:new(),
    [{client, Client} | Config1].

-spec end_per_testcase(atom(), ct_suite:ct_config()) -> ok.
end_per_testcase(_TestCase, _Config) ->
    ok = td_ct:teardown_testcase().

%%% Tests

%% ProcessEvent must return ok for a well-formed event.
-spec process_event_returns_ok(ct_suite:ct_config()) -> ok.
process_event_returns_ok(Config) ->
    Client = client(Config),
    Event = search_event(<<"subj_pe">>),
    ok = td_thrift_client:process_event(Event, Client).

%% After threshold is reached, GetContext must return a ThreatContext fragment
%% that deserializes into a ContextFragment containing the threat.
-spec get_context_returns_active_threats(ct_suite:ct_config()) -> ok.
get_context_returns_active_threats(Config) ->
    Client = client(Config),
    SubjectId = <<"subj_gc1">>,
    Event = search_event(SubjectId),
    [td_thrift_client:process_event(Event, Client) || _ <- lists:seq(1, 3)],
    td_ct:await_threat(c_gte3, td_ct:key(SubjectId), #{status => active, aggregate => 3}),
    ThreatCtx = td_thrift_client:get_context(SubjectId, Client),
    %% fragment must be present, otherwise the threat context is unusable
    ?assertMatch(#threats_ThreatContext{fragment = #ctx_ContextFragment{}}, ThreatCtx),
    Fragment = deserialize_context(ThreatCtx),
    Threats = get_threats_from_fragment(Fragment),
    ?assertEqual(1, ordsets:size(Threats)),
    [Threat] = ordsets:to_list(Threats),
    ?assertMatch(
        #'ctx_v1_Threat'{
            name = <<"c_gte3">>,
            level = high
        },
        Threat
    ),
    %% event_details must contain subject.id
    EventDetails = Threat#'ctx_v1_Threat'.event_details,
    ?assertMatch(#{?SUBJ := {string_value, SubjectId}}, EventDetails),
    %% a rule without a cooldown has no expiration
    ?assertEqual(undefined, Threat#'ctx_v1_Threat'.expiration).

%% After cooldown fires, GetContext must return an empty fragment.
%% c_cooldown: gte 2 events on export, cooldown.2s.
-spec get_context_excludes_expired_cooldown(ct_suite:ct_config()) -> ok.
get_context_excludes_expired_cooldown(Config) ->
    Client = client(Config),
    SubjectId = <<"subj_gc2">>,
    Event = export_event(SubjectId),
    [td_thrift_client:process_event(Event, Client) || _ <- lists:seq(1, 2)],
    td_ct:await_threat(c_cooldown, td_ct:key(SubjectId), #{status => active, aggregate => 2}),
    %% threat is visible immediately after activation
    ThreatCtx = td_thrift_client:get_context(SubjectId, Client),
    Fragment1 = deserialize_context(ThreatCtx),
    [Threat1] = ordsets:to_list(get_threats_from_fragment(Fragment1)),
    %% a rule with a cooldown carries the expiration as an RFC 3339 UTC timestamp
    Expiration = Threat1#'ctx_v1_Threat'.expiration,
    ?assertMatch(<<_:4/binary, "-", _:2/binary, "-", _:2/binary, "T", _:8/binary, "Z">>, Expiration),
    _ = calendar:rfc3339_to_system_time(binary_to_list(Expiration)),
    %% wait for the 2s cooldown to expire and the DB row to be deleted
    td_ct:await_threat(c_cooldown, td_ct:key(SubjectId), undefined, 4000),
    ThreatCtx2 = td_thrift_client:get_context(SubjectId, Client),
    Fragment2 = deserialize_context(ThreatCtx2),
    ?assertEqual(0, ordsets:size(get_threats_from_fragment(Fragment2))).

%% GetContext for a subject with no threats must return a fragment with an empty threat set.
-spec get_context_empty_when_no_threats(ct_suite:ct_config()) -> ok.
get_context_empty_when_no_threats(Config) ->
    Client = client(Config),
    ThreatCtx = td_thrift_client:get_context(<<"nobody">>, Client),
    %% an empty context still has to carry a fragment with an empty threat set
    ?assertMatch(#threats_ThreatContext{fragment = #ctx_ContextFragment{}}, ThreatCtx),
    Fragment = deserialize_context(ThreatCtx),
    ?assertEqual(0, ordsets:size(get_threats_from_fragment(Fragment))).

%% ClearContext must remove active threats so GetContext returns an empty fragment afterwards.
-spec clear_context_deactivates_threats(ct_suite:ct_config()) -> ok.
clear_context_deactivates_threats(Config) ->
    Client = client(Config),
    SubjectId = <<"subj_cc">>,
    OtherId = <<"subj_cc_other">>,
    [td_thrift_client:process_event(search_event(SubjectId), Client) || _ <- lists:seq(1, 3)],
    [td_thrift_client:process_event(search_event(OtherId), Client) || _ <- lists:seq(1, 3)],
    td_ct:await_threat(c_gte3, td_ct:key(SubjectId), #{status => active, aggregate => 3}),
    td_ct:await_threat(c_gte3, td_ct:key(OtherId), #{status => active, aggregate => 3}),
    ok = td_thrift_client:clear_context(SubjectId, Client),
    td_ct:await_threat(c_gte3, td_ct:key(SubjectId), undefined, 1000),
    %% subject's context is now empty
    ThreatCtx = td_thrift_client:get_context(SubjectId, Client),
    ?assertEqual(0, ordsets:size(get_threats_from_fragment(deserialize_context(ThreatCtx)))),
    %% other subject's context is untouched
    OtherCtx = td_thrift_client:get_context(OtherId, Client),
    ?assertEqual(1, ordsets:size(get_threats_from_fragment(deserialize_context(OtherCtx)))).

%%% Helpers

-spec client(ct_suite:ct_config()) -> td_thrift_client:client().
client(Config) ->
    proplists:get_value(client, Config).

-spec search_event(binary()) -> map().
search_event(SubjectId) ->
    #{
        <<"service.name">> => <<"b2b-api">>,
        <<"operation.id">> => <<"transaction-search">>,
        ?SUBJ => SubjectId
    }.

-spec export_event(binary()) -> map().
export_event(SubjectId) ->
    #{
        <<"service.name">> => <<"b2b-api">>,
        <<"operation.id">> => <<"transaction-export">>,
        ?SUBJ => SubjectId
    }.

-spec deserialize_context(bouncer_threats_thrift:'ThreatContext'()) -> bouncer_ctx_v1_thrift:'ContextFragment'().
deserialize_context(#threats_ThreatContext{fragment = #ctx_ContextFragment{content = Content}}) ->
    td_thrift_client:deserialize_fragment(Content).

-spec get_threats_from_fragment(bouncer_ctx_v1_thrift:'ContextFragment'()) ->
    ordsets:ordset(bouncer_ctx_v1_thrift:'Threat'()).
get_threats_from_fragment(#ctx_v1_ContextFragment{
    threats = #ctx_v1_ContextThreats{threats = Threats}
}) when Threats =/= undefined ->
    Threats;
get_threats_from_fragment(_Fragment) ->
    ordsets:new().
