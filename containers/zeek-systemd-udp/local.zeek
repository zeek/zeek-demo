# At this point we're not running in cluster mode, open the port directly.
redef LogAscii::use_json = T;

redef ignore_checksums = T;


# MDNS can cause a lot more queries than the default 25.
redef dns_max_queries = 100;


@load misc/loaded-scripts
@load misc/stats
