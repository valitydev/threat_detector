-module(td_sigma_parser).

-export([parse/1]).
-export([parse/2]).

-define(SEC_MINUTE, 60).
-define(SEC_HOUR, 3600).
-define(SEC_DAY, 86400).
-define(SEC_WEEK, 604800).
%% 30 * 86400, как в pySigma
-define(SEC_MONTH, 2592000).
%% 365 * 86400, как в pySigma
-define(SEC_YEAR, 31536000).

-spec parse(map()) -> map().
parse(Rule) ->
    parse(rule, Rule).

-type parse_type() :: atom() | {array, parse_type()} | {one_of_const, [term()]}.

-spec parse(Type :: parse_type(), Value :: term()) -> term().
parse(rule, Rule) when is_map(Rule) ->
    maps:fold(
        fun
            (<<"title">>, Value, Acc) -> Acc#{title => parse(string, Value)};
            (<<"id">>, Value, Acc) -> Acc#{id => parse(uuid, Value)};
            (<<"related">>, Value, Acc) -> Acc#{related => parse(related, Value)};
            (<<"name">>, Value, Acc) -> Acc#{name => parse(string, Value)};
            (<<"taxonomy">>, Value, Acc) -> Acc#{taxonomy => parse(string, Value)};
            (<<"status">>, Value, Acc) -> Acc#{status => parse(status, Value)};
            (<<"description">>, Value, Acc) -> Acc#{description => parse(string, Value)};
            (<<"license">>, Value, Acc) -> Acc#{license => parse(string, Value)};
            (<<"author">>, Value, Acc) -> Acc#{author => parse(string, Value)};
            (<<"references">>, Value, Acc) -> Acc#{references => parse(references, Value)};
            (<<"date">>, Value, Acc) -> Acc#{date => parse(date, Value)};
            (<<"modified">>, Value, Acc) -> Acc#{modified => parse(date, Value)};
            (<<"logsource">>, Value, Acc) -> Acc#{logsource => parse(logsource, Value)};
            (<<"fields">>, Value, Acc) -> Acc#{fields => parse(fields, Value)};
            (<<"falsepositives">>, Value, Acc) -> Acc#{falsepositives => parse(falsepositives, Value)};
            (<<"level">>, Value, Acc) -> Acc#{level => parse(level, Value)};
            (<<"tags">>, Value, Acc) -> Acc#{tags => parse(tags, Value)};
            (<<"scope">>, Value, Acc) -> Acc#{scope => parse(scope, Value)};
            %% must be one of: detection or correlation
            (<<"detection">>, Value, Acc) -> Acc#{detection => parse(detection, Value)};
            (<<"correlation">>, Value, Acc) -> Acc#{correlation => parse(correlation, Value)};
            (_, _, Acc) -> Acc
        end,
        #{},
        Rule
    );
parse(string, Value) when is_binary(Value) ->
    Value;
parse(uuid, Value) when is_binary(Value), byte_size(Value) =:= 36 ->
    case
        re:run(
            Value,
            <<
                "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
            >>,
            [{capture, none}]
        )
    of
        match -> Value;
        nomatch -> erlang:error({config_parse_error, bad_uuid, Value})
    end;
parse(related, #{<<"id">> := ID, <<"type">> := Type} = _Value) ->
    ExpectedValues = [
        <<"derived">>,
        <<"obsolete">>,
        <<"merged">>,
        <<"renamed">>,
        <<"similar">>
    ],
    #{
        id => parse(uuid, ID),
        type => parse({one_of_const, ExpectedValues}, Type)
    };
parse(status, Value) when is_binary(Value) ->
    ExpectedValues = [
        <<"stable">>,
        <<"test">>,
        <<"experimental">>,
        <<"deprecated">>,
        <<"unsupported">>
    ],
    parse({one_of_const, ExpectedValues}, Value);
parse(references, Value) when is_list(Value) ->
    parse({array, string}, Value);
parse(date, Value) when is_binary(Value) ->
    case
        re:run(
            Value,
            <<"^\\d{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])$">>,
            [{capture, none}]
        )
    of
        match ->
            Value;
        nomatch ->
            erlang:error({config_parse_error, bad_date, Value})
    end;
parse(logsource, Value) when is_map(Value) ->
    maps:fold(
        fun
            (<<"product">>, V, Acc) -> Acc#{product => parse(string, V)};
            (<<"category">>, V, Acc) -> Acc#{category => parse(string, V)};
            (<<"service">>, V, Acc) -> Acc#{service => parse(string, V)}
        end,
        #{},
        Value
    );
parse(detection, Value) when is_map(Value) ->
    maps:fold(
        fun
            (<<"condition">>, V, Acc) -> Acc#{condition => parse(detection_condition, V)};
            (Selection, V, Acc) -> Acc#{Selection => parse(selection, V)}
        end,
        #{},
        Value
    );
parse(selection, Value) when is_list(Value) ->
    %% selection by keywords
    erlang:error({config_parse_error, bad_selection, selection_by_keywords_not_supported});
parse(selection, Value) when is_map(Value) ->
    %% selection by field/field list
    maps:fold(
        fun
            (FieldName, FieldValue, Acc) when is_binary(FieldName), is_list(FieldValue) ->
                Acc#{FieldName => parse({array, selection_value}, FieldValue)};
            (FieldName, FieldValue, Acc) when is_binary(FieldName) ->
                Acc#{FieldName => [parse(selection_value, FieldValue)]}
        end,
        #{},
        Value
    );
parse(selection_value, Value) when
    is_integer(Value);
    is_float(Value);
    is_boolean(Value);
    is_binary(Value)
->
    Value;
parse(correlation, #{<<"type">> := _, <<"rules">> := _, <<"timespan">> := _} = Value) ->
    maps:fold(
        fun
            (<<"type">>, V, Acc) -> Acc#{type => parse(correlation_type, V)};
            (<<"rules">>, V, Acc) -> Acc#{rules => parse({array, string}, V)};
            (<<"timespan">>, V, Acc) -> Acc#{timespan => parse(timespan, V)};
            (<<"group-by">>, V, Acc) -> Acc#{group_by => parse(group_by, V)};
            (<<"condition">>, V, Acc) -> Acc#{condition => parse(correlation_condition, V)};
            (_, _, Acc) -> Acc
        end,
        #{},
        Value
    );
parse(correlation_type, Value) ->
    ExpectedValues = [
        %%% not supported yet
        %<<"value_percentile">>,
        %<<"value_avg">>,
        %<<"value_sum">>,
        %<<"value_count">>,
        %<<"temporal_ordered">>,
        %<<"temporal">>,
        <<"event_count">>
    ],
    parse({one_of_const, ExpectedValues}, Value);
parse(group_by, Value) when is_list(Value) ->
    %% It is expected that the subject identifier
    %% must always be present in the grouping conditions
    case lists:member(<<"subject.id">>, Value) of
        true ->
            parse({array, string}, Value);
        false ->
            parse({array, string}, [<<"subject.id">> | Value])
    end;
parse(correlation_condition, Value) when is_map(Value) ->
    maps:fold(
        fun
            %% must be one_of: gt, gte, lt, lte, eq, neq
            (<<"gt">>, Lim, Acc) -> Acc#{check_fun => fun(V) -> V > Lim end};
            (<<"gte">>, Lim, Acc) -> Acc#{check_fun => fun(V) -> V >= Lim end};
            (<<"lt">>, Lim, Acc) -> Acc#{check_fun => fun(V) -> V < Lim end};
            (<<"lte">>, Lim, Acc) -> Acc#{check_fun => fun(V) -> V =< Lim end};
            (<<"eq">>, Lim, Acc) -> Acc#{check_fun => fun(V) -> V =:= Lim end};
            (<<"neq">>, Lim, Acc) -> Acc#{check_fun => fun(V) -> V =/= Lim end}
            %% field is required for correlation types:
            %% value_percentile, value_avg, value_sum, value_count
            %% not supported yet
            %(<<"field">>, V, Acc) -> Acc#{field => V}
        end,
        #{},
        Value
    );
parse(timespan, Value) when is_binary(Value) ->
    case
        re:run(
            Value,
            <<"^([0-9]+)([smhdwMy])$">>,
            [{capture, [1, 2], binary}]
        )
    of
        {match, [Digits, UnitBin]} ->
            Num = binary_to_integer(Digits),
            to_seconds(Num, UnitBin);
        nomatch ->
            erlang:error({config_parse_error, bad_timespan, Value})
    end;
parse({array, Type}, List) ->
    [parse(Type, V) || V <- List];
parse({one_of_const, Expected}, Value) ->
    case lists:member(Value, Expected) of
        true ->
            Value;
        false ->
            Error = {{got, Value}, {expected_one_of, Expected}},
            erlang:error({config_parse_error, unexpected_value, Error})
    end;
parse(detection_condition, Value) when is_binary(Value) ->
    %% TODO
    Value;
parse(fields, Value) when is_list(Value) ->
    parse({array, string}, Value);
parse(falsepositives, Value) when is_list(Value) ->
    parse({array, string}, Value);
parse(level, Value) when is_binary(Value) ->
    ExpectedValues = [
        <<"informational">>,
        <<"low">>,
        <<"medium">>,
        <<"high">>,
        <<"critical">>
    ],
    parse({one_of_const, ExpectedValues}, Value);
parse(tags, Value) when is_list(Value) ->
    parse({array, string}, Value);
parse(scope, Value) when is_list(Value) ->
    parse({array, string}, Value);
parse(Type, Value) ->
    erlang:error({config_parse_error, unknown, {{type, Type}, {value, Value}}}).

%%

to_seconds(N, <<"s">>) -> N * 1;
to_seconds(N, <<"m">>) -> N * ?SEC_MINUTE;
to_seconds(N, <<"h">>) -> N * ?SEC_HOUR;
to_seconds(N, <<"d">>) -> N * ?SEC_DAY;
to_seconds(N, <<"w">>) -> N * ?SEC_WEEK;
to_seconds(N, <<"M">>) -> N * ?SEC_MONTH;
to_seconds(N, <<"y">>) -> N * ?SEC_YEAR.
