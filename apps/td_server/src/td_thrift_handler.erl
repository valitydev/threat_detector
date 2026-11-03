-module(td_thrift_handler).

-behaviour(woody_server_thrift_handler).

-include_lib("bouncer_proto/include/bouncer_ctx_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_ctx_v1_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_threats_thrift.hrl").

-export([handle_function/4]).

-spec handle_function(woody:func(), woody:args(), woody_context:ctx(), woody:options()) ->
    {ok, woody:result()} | no_return().
handle_function(Func, Args, WoodyCtx, Opts) ->
    scoper:scope(
        threat_detector,
        fun() -> handle_function_(Func, Args, WoodyCtx, Opts) end
    ).

handle_function_('ProcessEvent', {EncodedEvent}, _WoodyCtx, _Opts) ->
    Event = decode(event, EncodedEvent),
    ok = threat_detector:process_event(Event),
    {ok, ok};
handle_function_('GetContext', {SubjectID}, _WoodyCtx, _Opts) ->
    {ok, Threats} = threat_detector:get_threats(SubjectID),
    Fragment = encode(fragment, Threats),
    Context = encode(context, Fragment),
    ThreatContext = #threats_ThreatContext{fragment = Context},
    {ok, ThreatContext};
handle_function_('ClearContext', {SubjectID}, _WoodyCtx, _Opts) ->
    ok = threat_detector:clear_threats(SubjectID),
    {ok, ok}.

decode(event, Event) ->
    maps:map(
        fun(_K, {_Type, Value}) -> Value end,
        Event
    ).

encode(context, Fragment) ->
    #ctx_ContextFragment{
        type = v1_thrift_binary,
        content = serialize_fragment(Fragment)
    };
encode(fragment, Threats) ->
    EncodedThreats = [encode(threat, Threat) || Threat <- Threats],
    #ctx_v1_ContextFragment{
        threats = #ctx_v1_ContextThreats{
            threats = ordsets:from_list(EncodedThreats)
        }
    };
encode(threat, Threat) ->
    #{
        rule := RuleName,
        level := Level,
        details := Details
    } = Threat,
    #'ctx_v1_Threat'{
        name = RuleName,
        level = encode(level, Level),
        event_details = encode(details, Details),
        tags = maps:get(tags, Threat, undefined)
    };
encode(level, <<"critical">>) ->
    critical;
encode(level, <<"high">>) ->
    high;
encode(level, <<"medium">>) ->
    medium;
encode(level, <<"low">>) ->
    low;
encode(level, <<"informational">>) ->
    informational;
encode(details, Details) ->
    Map = lists:foldl(
        fun(Pair, Acc) ->
            maps:merge(Acc, Pair)
        end,
        #{},
        Details
    ),
    maps:map(
        fun(_K, V) -> encode(attribute_value, V) end,
        Map
    );
encode(attribute_value, V) when is_binary(V) ->
    {string_value, V};
encode(attribute_value, V) when is_integer(V) ->
    {integer_value, V};
encode(attribute_value, V) when is_float(V) ->
    {double_value, V};
encode(attribute_value, V) when is_boolean(V) ->
    {bool_value, V}.

serialize_fragment(Fragment) ->
    Type = {struct, struct, {bouncer_ctx_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(),
    {ok, Codec1} = thrift_strict_binary_codec:write(Codec, Type, Fragment),
    thrift_strict_binary_codec:close(Codec1).
