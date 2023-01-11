# At this point we're not running in cluster mode, open the port directly.
redef Broker::metrics_port = 9911/tcp;

redef LogAscii::use_json=T;

@load misc/loaded-scripts

@load ./scripts/telemetry
