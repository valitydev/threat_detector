-module(threat_detector).

-include("threat_detector.hrl").

-export([process_event/1, get_threats/1, clear_threats/1]).

-export_type([threats/0]).

-type threats() :: #{
    rule := binary(),
    level := binary(),
    details := [map()],
    tags => [term()]
}.

-define(DEFAULT_DB_POOL, default_pool).

%%% API

-spec process_event(event()) -> ok.
process_event(Event) ->
    td_selection:produce(Event).

%% Returns all active threats of the subject.
-spec get_threats(binary()) -> {ok, [threats()]} | {error, term()}.
get_threats(SubjectId) ->
    SQL =
        "SELECT rule, level::text, details, tags FROM threats "
        "WHERE subject_id = $1 AND (expires_at IS NULL OR expires_at > now())",
    case query(SQL, [SubjectId]) of
        {ok, _Cols, Rows} ->
            {ok, [to_threat(Row) || Row <- Rows]};
        {error, _} = Error ->
            Error
    end.

%% Deactivates all threats of the subject in the corresponding correlators.
-spec clear_threats(binary()) -> ok | {error, term()}.
clear_threats(SubjectId) ->
    SQL = "SELECT rule, details FROM threats WHERE subject_id = $1",
    case query(SQL, [SubjectId]) of
        {ok, _Cols, Rows} ->
            lists:foreach(fun cancel_threat/1, Rows);
        {error, _} = Error ->
            Error
    end.

%%% Internal functions

query(SQL, Params) ->
    Pool = application:get_env(threat_detector, db_pool, ?DEFAULT_DB_POOL),
    epg_pool:query(Pool, SQL, Params).

to_threat({Rule, Level, Details, Tags}) ->
    Threat = #{
        rule => Rule,
        level => Level,
        details => jsx:decode(Details)
    },
    case jsx:decode(Tags) of
        [] ->
            Threat;
        DecodedTags ->
            Threat#{tags => DecodedTags}
    end.

cancel_threat({Rule, Details}) ->
    RegName = erlang:binary_to_atom(Rule),
    GroupingKey = td_correlation:grouping_key_from_details(Details),
    ok = td_correlation:cancel_threat(RegName, GroupingKey).
