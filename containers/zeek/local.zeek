# At this point we're not running in cluster mode, open the port directly.
redef Broker::metrics_port = 9911/tcp;

redef LogAscii::use_json=T;


# MDNS can cause a lot more queries than the default 25.
redef dns_max_queries = 100;


@load misc/loaded-scripts

@load ./scripts/telemetry
