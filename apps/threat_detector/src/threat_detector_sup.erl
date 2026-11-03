%%%-------------------------------------------------------------------
%% @doc tpl top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(threat_detector_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).
-define(DEFAULT_RULES_PATH, "config/rules.yaml").
-define(MIGRATION_REALM, "threat_detector").

-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    ok = db_init(),
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    SupFlags = #{
        strategy => one_for_all,
        intensity => 0,
        period => 1
    },
    SelectorSpec = #{
        id => selector,
        start => {td_selection, start_link, []}
    },
    OrderedSpecs = ordered_specs(),
    {ok, {SupFlags, [SelectorSpec | OrderedSpecs]}}.

%% internal functions

db_init() ->
    DbRef = application:get_env(threat_detector, database, threat_detector),
    {ok, Databases} = application:get_env(epg_connector, databases),
    DbOpts = maps:get(DbRef, Databases),
    PrivDir = code:priv_dir(threat_detector),
    MigrationsDir = filename:join([PrivDir, "migrations"]),
    {ok, _} = epg_migrator:perform(?MIGRATION_REALM, DbOpts, [], MigrationsDir),
    ok.

ordered_specs() ->
    RulesPath = application:get_env(threat_detector, config_path, ?DEFAULT_RULES_PATH),
    YamlDocs = yamerl:decode_file(RulesPath, [{str_node_as_binary, utf8}, {map_node_format, map}]),
    Graph = digraph:new(),
    SpecsMap = lists:foldl(
        fun
            (#{<<"name">> := Name} = _Rule, Acc) when is_map_key(Name, Acc) ->
                erlang:error({config_parse_error, duplicate_rule_name, Name});
            (#{<<"name">> := Name, <<"detection">> := _} = Rule, Acc) ->
                _ = digraph:add_vertex(Graph, Name),
                Acc#{Name => spec_detection(Name, td_sigma_parser:parse(Rule))};
            (#{<<"name">> := Name, <<"correlation">> := Correlation} = Rule, Acc) ->
                _ = digraph:add_vertex(Graph, Name),
                Inputs = maps:get(<<"rules">>, Correlation),
                lists:foreach(
                    fun(Input) ->
                        _ = digraph:add_vertex(Graph, Input),
                        _ = digraph:add_edge(Graph, Input, Name)
                    end,
                    Inputs
                ),
                Acc#{Name => spec_correlation(Name, td_sigma_parser:parse(Rule))};
            (Rule, _Acc) ->
                erlang:error({config_parse_error, unsupported_rule, Rule})
        end,
        #{},
        YamlDocs
    ),
    case digraph_utils:topsort(Graph) of
        false ->
            erlang:error({config_parse_error, bad_config, correlation_cycle_detected});
        Order ->
            digraph:delete(Graph),
            [maps:get(Name, SpecsMap) || Name <- Order]
    end.

reg_name(Bin) ->
    erlang:binary_to_atom(Bin).

spec_detection(Name, Rule) ->
    #{
        id => Name,
        start => {td_detection, start_link, [reg_name(Name), Rule]}
    }.

spec_correlation(Name, Rule) ->
    #{
        id => Name,
        start => {td_correlation, start_link, [reg_name(Name), Rule]}
    }.
