--io.stderr:write("baseconfig.lua loaded\n")
include('snort_defaults.lua')
include('talos_functions.lua')
include('file_magic.lua')

env = getfenv()

detection = { }
search_engine = { }
event_queue = { }
normalizer = { }

network = { }

stream = { }
stream_ip = { }
stream_icmp = { }
stream_tcp = { }
stream_udp = { }
stream_user = { }
stream_file = { }

appid = { }

arp_spoof = { }

dns = { }

http_inspect = { }
-- list of javascript functions to not normalize using the new javascript normalizer
-- that populates js_data buffer.  At this time, we are running both normalizers (though
-- js_data is actually a JIT buffer so if no rules use it, no buffer will be created)
if (TALOS.functions.minsnortver(3,1,19,0,0) and TALOS.functions.stopsnortver(3,1,47,0,0)) then
   http_inspect.js_norm_ident_ignore = default_js_norm_ident_ignore
end

-- list of javascript properties to not normalize using the new javascript normalizer
-- that populates js_data buffer.
if (TALOS.functions.minsnortver(3,1,30,0,0) and TALOS.functions.stopsnortver(3,1,47,0,0)) then
   http_inspect.js_norm_prop_ignore = default_js_norm_prop_ignore
end

if MISSING_HTTP2 == nil then
   http2_inspect = { }
end

-- javascript normalization got moved to its own thing in 3.1.47.0 so it can be used everywhere
if(TALOS.functions.minsnortver(3,1,47,0,0)) then
   js_norm = {
      ident_ignore = default_js_norm_ident_ignore,
      prop_ignore = default_js_norm_prop_ignore
   }
end

imap = { }
pop = { }

rpc_decode = { }
ssh = { }
ssl = { }

telnet = { }

dce_smb = { }
dce_tcp = { }
dce_udp = { }
dce_http_proxy = { }
dce_http_server = { }

---- Industrial Control Systems (ICS) protocols
--sip = { }
--dnp3 = { }
--modbus = { }
--s7commplus = { }
--cip = { }
--
--if (TALOS.functions.minsnortver(3,1,7,0,0) or (TALOS.functions.minsnortver(3,1,0,1,174) and TALOS.functions.stopsnortver(3,1,1,0,0))) then
--   iec104 = { }
--end
--
--if (TALOS.functions.minsnortver(3,1,28,0,0) or (TALOS.functions.minsnortver(3,1,21,1,120) and TALOS.functions.stopsnortver(3,1,22,0,0))) then
--   mms = { }
--end
--
--gtp_inspect = default_gtp

port_scan = default_med_port_scan

smtp = default_smtp

ftp_server = default_ftp_server
ftp_client = { }
ftp_data = { }

-- see file_magic.lua for file id rules
if TALOS.functions.minsnortver(3,1,35,0,0) then
   file_id = { rules_file = 'file_magic.rules'}
else
   file_id = { file_rules = file_magic }
end

if TALOS.functions.minsnortver(3,1,28,0,0) then
   file_policy = { }
end

---------------------------------------------------------------------------
-- 4. configure performance
---------------------------------------------------------------------------

-- use latency to monitor / enforce packet and rule thresholds
latency = { }

-- use these to capture perf data for analysis and tuning
--profiler = { }
perf_monitor = { }


---------------------------------------------------------------------------
-- 3. configure bindings
---------------------------------------------------------------------------

wizard = default_wizard
TALOS.functions.add_binder_entries()

---------------------------------------------------------------------------
-- 5. configure detection
---------------------------------------------------------------------------
-- this is also in load_ips.lua, where it belongs.  Remove this at some point.
references = default_references
classifications = default_classifications

