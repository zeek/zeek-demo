redef ignore_checksums = T;
redef LogAscii::use_json = T;

# MDNS can cause a lot more queries than the default 25.
redef dns_max_queries = 100;

@load misc/loaded-scripts
@load misc/stats

# Verbose cluster metrics!
redef Cluster::Telemetry::core_metrics += {
	Cluster::Telemetry::VERBOSE,
};
