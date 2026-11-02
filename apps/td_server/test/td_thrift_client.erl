-module(td_thrift_client).

%% API
-export([new/0]).
-export([process_event/2, get_context/2, clear_context/2]).
-export([deserialize_fragment/1]).

-include_lib("bouncer_proto/include/bouncer_threats_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_ctx_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_ctx_v1_thrift.hrl").

-export_type([client/0]).

-type client() :: woody_context:ctx().

-spec new() -> client().
new() ->
    woody_context:new().

-spec process_event(map(), client()) -> ok | no_return().
process_event(Event, Client) ->
    EncodedEvent = encode_event(Event),
    call('ProcessEvent', {EncodedEvent}, Client).

-spec get_context(binary(), client()) -> bouncer_threats_thrift:'ThreatContext'() | no_return().
get_context(SubjectID, Client) ->
    call('GetContext', {SubjectID}, Client).

-spec clear_context(binary(), client()) -> ok | no_return().
clear_context(SubjectID, Client) ->
    call('ClearContext', {SubjectID}, Client).

%% Decodes the binary content of a ContextFragment into a ctx_v1_ContextFragment record.
-spec deserialize_fragment(binary()) -> bouncer_ctx_v1_thrift:'ContextFragment'().
deserialize_fragment(Binary) ->
    Type = {struct, struct, {bouncer_ctx_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(Binary),
    {ok, Fragment, _Codec1} = thrift_strict_binary_codec:read(Codec, Type),
    Fragment.

%%% Internal

-spec call(atom(), tuple(), client()) -> woody:result() | no_return().
call(Function, Args, Client) ->
    Call = {{bouncer_threats_thrift, 'ThreatDetector'}, Function, Args},
    Opts = #{
        url => <<"http://localhost:8023/v1/threat_detector">>,
        event_handler => scoper_woody_event_handler,
        transport_opts => #{max_connections => 100}
    },
    case woody_client:call(Call, Opts, Client) of
        {ok, Response} ->
            Response;
        {exception, Exception} ->
            throw(Exception)
    end.

-spec encode_event(map()) -> map().
encode_event(Event) ->
    maps:map(fun(_K, V) -> encode_event_attribute_value(V) end, Event).

encode_event_attribute_value(V) when is_binary(V) -> {string_value, V};
encode_event_attribute_value(V) when is_integer(V) -> {integer_value, V};
encode_event_attribute_value(V) when is_float(V) -> {double_value, V};
encode_event_attribute_value(V) when is_boolean(V) -> {bool_value, V}.
