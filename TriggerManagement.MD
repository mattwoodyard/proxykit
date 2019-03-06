






PUT /v1/trigger - Create a new trigger

  { "style": TriggerDefintionEnum,
    "target": TriggerTargetDefinition
    "condition": "(match expression)"
  } 

  TriggerDefintionEnum
    Request - Trigger on requests, matches will wait for a response from the target
    Response - Trigger on response, matches will wait for a result from the target
    RequestAndResponse - Trigger on requests and response, matches will wait for a response from the target
    RequestAsync - Trigger on requests, matches will NOT wait for a response from the target 
    ResponseAsync - Trigger on responses, matches will NOT wait for a response from the target 
    RequestAndResponseAsync - Trigger on requests and response, matches NOT will wait for a response from the target


  TriggerTargetDefinition 
    { "type": "url", "value": "the url to send the request to as a msgpack'd blob"}

    Not yet implemented
    { "type": "internal", "value": "the  name of an internal feature for processing" }
    { "type": "ebpf", "value": "a ebpf binary to use as the filter"}
    { "type": "lua", "value": "a lua callable to use as the filter"}



GET /v1/triggers - Get the currently active triggers 
DELETE /v1/triggers/:id - remove an active trigger


