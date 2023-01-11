@load base/frameworks/telemetry

# Log writes
global log_writes_cf = Telemetry::register_counter_family([
    $prefix="zeek",
    $name="log_writes",
    $unit="1",
    $help_text="Number of log writes per stream",
    $labels=vector("log_id"),
]);

hook Log::log_stream_policy(rec: any, id: Log::ID)
    {
    local log_id = to_lower(gsub(cat(id), /:+/, "_"));
    Telemetry::counter_family_inc(log_writes_cf, vector(log_id));
    }

# Analyzer confirmations / violations
global analyzer_violations_cf = Telemetry::register_counter_family([
    $prefix="zeek",
    $name="analyzer_violations",
    $unit="1",
    $help_text="Number of analyzer violations broken down by analyzer",
    $labels=vector("analyzer"),
]);

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
    {
    local analyzer = to_lower(gsub(cat(atype), /:+/, "_"));
    Telemetry::counter_family_inc(analyzer_violations_cf, vector(analyzer));
    }

# Analyzer confirmations broken down by analyzer
global analyzer_confirmations_cf = Telemetry::register_counter_family([
    $prefix="zeek",
    $name="analyzer_confirmations",
    $unit="1",
    $help_text="Number of analyzer confirmations broken down by analyzer",
    $labels=vector("analyzer"),
]);

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
    {
    local analyzer = to_lower(gsub(cat(atype), /:+/, "_"));
    Telemetry::counter_family_inc(analyzer_confirmations_cf, vector(analyzer));
    }

module Tunnel;

global tunnels_active_size_gf = Telemetry::register_gauge_family([
    $prefix="zeek",
    $name="monitored_tunnels_active",
    $unit="1",
    $help_text="Number of currently active tunnels as tracked in Tunnel::active",
]);

global tunnels_active_size_gauge = Telemetry::gauge_with(tunnels_active_size_gf);

global tunnels_active_footprint_gf = Telemetry::register_gauge_family([
    $prefix="zeek",
    $name="monitored_tunnels_active_footprint",
    $unit="1",
    $help_text="Footprint of the Tunnel::active table",
]);

global tunnels_active_footprint_gauge = Telemetry::gauge_with(tunnels_active_footprint_gf);

hook Telemetry::sync() {

    Telemetry::gauge_set(tunnels_active_size_gauge, |Tunnel::active|);
    Telemetry::gauge_set(tunnels_active_footprint_gauge, val_footprint(Tunnel::active));
}
