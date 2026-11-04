-module(td_ct).

%% Suite lifecycle
-export([init_suite/0, end_suite/0]).
-export([setup_testcase/2, teardown_testcase/0]).

%% Event and key builders
-export([search_event/1, export_event/1, unauthorized_event/3]).
-export([key/1, token_key/3]).

%% Event production and polling
-export([produce/2]).
-export([await_threat/3, await_threat/4]).

%% DB helpers
-export([db_opts/0]).
-export([threat_hash/1]).
-export([insert_threat/3]).
-export([clear_all_threats/0, clear_threats/2, count_threats/3]).

%% Rule config builders
-export([rules_for/1]).

-define(SUBJ, <<"subject.id">>).
-define(AUTH_TYPE, <<"subject.auth_type">>).
-define(AUTH_SIG, <<"subject.auth_signature">>).
-define(DB_HOST, "postgres").
-define(DB_PORT, 5432).
-define(DB_NAME, "threat_detector").
-define(DB_USER, "threat_detector").
-define(DB_PASSWORD, "threat_detector").
-define(DB_POOL, default_pool).
-define(AWAIT_MS, 3000).

%%% Suite lifecycle

-spec db_opts() -> epgsql:connect_opts().
db_opts() ->
    #{
        host => ?DB_HOST,
        port => ?DB_PORT,
        database => ?DB_NAME,
        username => ?DB_USER,
        password => ?DB_PASSWORD
    }.

-spec init_suite() -> ok.
init_suite() ->
    DbOpts = db_opts(),
    ok = application:set_env(epg_connector, databases, #{threat_detector => DbOpts}),
    ok = application:set_env(epg_connector, pools, #{?DB_POOL => #{database => threat_detector, size => 5}}),
    {ok, _} = application:ensure_all_started(epg_connector),
    {ok, _} = application:ensure_all_started(epg_migrator),
    ok.

-spec end_suite() -> ok.
end_suite() ->
    _ = application:stop(epg_migrator),
    _ = application:stop(epg_connector),
    ok = application:unset_env(epg_connector, databases),
    ok = application:unset_env(epg_connector, pools),
    ok.

%% Writes the rules yaml and sets config_path env; does NOT start threat_detector.
%% The caller decides whether to start the app (allows suites with startup-failure tests).
-spec setup_testcase(atom(), ct_suite:ct_config()) -> ct_suite:ct_config().
setup_testcase(TestCase, Config) ->
    %% rows left by a previous case must not be restored by td_correlation:init/1
    ok = clear_all_threats(),
    Path = filename:join(proplists:get_value(priv_dir, Config), "rules.yaml"),
    ok = file:write_file(Path, rules_for(TestCase)),
    ok = application:set_env(threat_detector, config_path, Path),
    Config.

-spec teardown_testcase() -> ok.
teardown_testcase() ->
    _ = application:stop(threat_detector),
    ok = application:unset_env(threat_detector, config_path),
    ok = clear_all_threats(),
    ok.

%%% Event and key builders

-spec search_event(binary()) -> map().
search_event(SubjectId) ->
    #{
        <<"service.name">> => <<"b2b-api">>,
        <<"operation.id">> => <<"transaction-search">>,
        ?SUBJ => SubjectId
    }.

-spec export_event(binary()) -> map().
export_event(SubjectId) ->
    (search_event(SubjectId))#{<<"operation.id">> => <<"transaction-export">>}.

-spec unauthorized_event(binary(), binary(), binary()) -> map().
unauthorized_event(SubjectId, AuthType, AuthSig) ->
    (search_event(SubjectId))#{
        <<"authorization.result">> => <<"deny">>,
        ?AUTH_TYPE => AuthType,
        ?AUTH_SIG => AuthSig
    }.

-spec key(binary()) -> [{binary(), binary()}].
key(SubjectId) ->
    [{?SUBJ, SubjectId}].

-spec token_key(binary(), binary(), binary()) -> [{binary(), binary()}].
token_key(SubjectId, AuthType, AuthSig) ->
    [{?SUBJ, SubjectId}, {?AUTH_TYPE, AuthType}, {?AUTH_SIG, AuthSig}].

%%% Event production and polling

-spec produce(map(), pos_integer()) -> ok.
produce(Event, Count) ->
    lists:foreach(fun(_) -> ok = td_selection:produce(Event) end, lists:seq(1, Count)).

-spec await_threat(atom(), term(), term()) -> ok.
await_threat(Rule, Key, Expected) ->
    await_threat(Rule, Key, Expected, ?AWAIT_MS).

-spec await_threat(atom(), term(), term(), non_neg_integer()) -> ok.
await_threat(Rule, Key, Expected, TimeoutMs) ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    await_threat_loop(Rule, Key, Expected, Deadline).

await_threat_loop(Rule, Key, Expected, Deadline) ->
    case td_correlation:get_threat(Rule, Key) of
        Expected ->
            ok;
        Current ->
            case erlang:monotonic_time(millisecond) > Deadline of
                true ->
                    ct:fail({unexpected_threat, {rule, Rule}, {key, Key}, {expected, Expected}, {got, Current}});
                false ->
                    timer:sleep(20),
                    await_threat_loop(Rule, Key, Expected, Deadline)
            end
    end.

%%% DB helpers

-spec threat_hash(term()) -> binary().
threat_hash(Key) ->
    crypto:hash(sha256, term_to_binary(Key, [{minor_version, 2}])).

-spec insert_threat(atom(), binary(), [{binary(), term()}]) -> ok.
insert_threat(Pool, Rule, Key) ->
    Details = jsx:encode([#{K => V} || {K, V} <- Key]),
    SubjectId = proplists:get_value(?SUBJ, Key, <<>>),
    SQL =
        "INSERT INTO threats "
        "(rule, rule_instance_hash, subject_id, level, details, tags, expires_at) "
        "VALUES ($1, $2, $3, $4::text::threat_level, $5, $6, $7)",
    {ok, 1} = epg_pool:query(
        Pool, SQL, [Rule, threat_hash(Key), SubjectId, <<"high">>, Details, <<"[]">>, null]
    ),
    ok.

-spec clear_all_threats() -> ok.
%% Uses a dedicated connection, not the pool: cleanup must not depend on pool state.
clear_all_threats() ->
    {ok, Conn} = epgsql:connect(db_opts()),
    try
        case epgsql:squery(Conn, "DELETE FROM threats") of
            {ok, _} ->
                ok;
            %% the table is created by the migration on the first start of threat_detector
            {error, {error, _Severity, <<"42P01">>, undefined_table, _Msg, _Extra}} ->
                ok
        end
    after
        ok = epgsql:close(Conn)
    end.

-spec clear_threats(atom(), binary()) -> ok.
clear_threats(Pool, Rule) ->
    {ok, _} = epg_pool:query(Pool, "DELETE FROM threats WHERE rule = $1", [Rule]),
    ok.

-spec count_threats(atom(), binary(), [{binary(), term()}]) -> integer().
count_threats(Pool, Rule, Key) ->
    SQL = "SELECT count(*) FROM threats WHERE rule = $1 AND rule_instance_hash = $2",
    {ok, _Cols, [{Count}]} = epg_pool:query(Pool, SQL, [Rule, threat_hash(Key)]),
    Count.

%%% Rule configs (minimal time granularity is one second)

-spec rules_for(atom()) -> binary().
rules_for(multi_correlation_activate) ->
    iolist_to_binary([
        det("all", [{"op.service", "b2b"}, {"op.id", "get"}]),
        det("unknown", [{"op.service", "b2b"}, {"op.id", "get"}, {"op.result", "not_found"}]),
        det("unauth", [{"op.service", "b2b"}, {"op.id", "get"}, {"op.result", "auth_fail"}]),
        corr("too_many_all", "all", ["subject.id"], "1s", {"gte", 10}, ["cooldown.3s"]),
        corr("too_many_unknown", "unknown", ["subject.id"], "1s", {"gte", 3}, ["brutforce.transaction"]),
        corr("too_many_unauth", "unauth", ["subject.id"], "1s", {"gte", 3}, ["brutforce.merchant"])
    ]);
rules_for(start_fails_on_cycle) ->
    iolist_to_binary([
        corr("c1", "c2", ["subject.id"], "1s", {"gte", 1}, []),
        corr("c2", "c1", ["subject.id"], "1s", {"gte", 1}, [])
    ]);
rules_for(start_fails_on_duplicate_name) ->
    iolist_to_binary([
        det("dup", [{"service.name", "b2b-api"}]),
        det("dup", [{"service.name", "b2b-api"}])
    ]);
rules_for(TestCase) when
    TestCase =:= get_threats_returns_active;
    TestCase =:= get_threats_excludes_expired_cooldown;
    TestCase =:= get_threats_not_modified_after_restart;
    TestCase =:= clear_threats_deactivates_all;
    TestCase =:= process_event_returns_ok;
    TestCase =:= get_context_returns_active_threats;
    TestCase =:= get_context_excludes_expired_cooldown;
    TestCase =:= get_context_empty_when_no_threats;
    TestCase =:= clear_context_deactivates_threats
->
    %% each correlator listens to its own detection: one event activates exactly one threat
    Search = [{"service.name", "b2b-api"}, {"operation.id", "transaction-search"}],
    Export = [{"service.name", "b2b-api"}, {"operation.id", "transaction-export"}],
    Subj = ["subject.id"],
    iolist_to_binary([
        det("search_request", Search),
        det("export_request", Export),
        corr("c_gte3", "search_request", Subj, "1m", {"gte", 3}, []),
        corr("c_cooldown", "export_request", Subj, "1m", {"gte", 2}, ["cooldown.2s"])
    ]);
rules_for(_TestCase) ->
    Search = [{"service.name", "b2b-api"}, {"operation.id", "transaction-search"}],
    Subj = ["subject.id"],
    iolist_to_binary([
        det("search_request", Search),
        det("unauthorized", Search ++ [{"authorization.result", "deny"}]),
        corr("c_gte3", "search_request", Subj, "3s", {"gte", 3}, []),
        corr("c_gt3", "search_request", Subj, "1m", {"gt", 3}, []),
        corr("c_lte2", "search_request", Subj, "1m", {"lte", 2}, []),
        corr("c_eq2", "search_request", Subj, "1m", {"eq", 2}, []),
        corr("c_neq0", "search_request", Subj, "1m", {"neq", 0}, []),
        corr("c_window", "search_request", Subj, "1s", {"gte", 3}, []),
        corr("c_cooldown", "search_request", Subj, "1m", {"gte", 2}, ["cooldown.2s"]),
        corr(
            "c_token",
            "unauthorized",
            ["subject.id", "subject.auth_type", "subject.auth_signature"],
            "1m",
            {"gte", 3},
            []
        )
    ]).

det(Name, Fields) ->
    [
        "---\nname: ",
        Name,
        "\ntitle: ",
        Name,
        "\ndetection:\n  selection:\n",
        [["    ", K, ": ", V, "\n"] || {K, V} <- Fields],
        "  condition: selection\nlevel: low\n"
    ].

corr(Name, Input, GroupBy, Timespan, {Op, Limit}, Tags) ->
    [
        "---\nname: ",
        Name,
        "\ntitle: ",
        Name,
        "\ncorrelation:\n  type: event_count\n  rules:\n    - ",
        Input,
        "\n  group-by:\n",
        [["    - ", G, "\n"] || G <- GroupBy],
        "  timespan: ",
        Timespan,
        "\n  condition:\n    ",
        Op,
        ": ",
        integer_to_list(Limit),
        "\nlevel: high\n",
        tags(Tags)
    ].

tags([]) ->
    [];
tags(Tags) ->
    ["tags:\n", [["  - ", T, "\n"] || T <- Tags]].
