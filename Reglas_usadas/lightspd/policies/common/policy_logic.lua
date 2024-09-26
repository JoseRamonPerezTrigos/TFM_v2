--io.stderr:write("policy_logic.lua loaded\n")
include('talos_functions.lua')

-- This date is used as the version information for all policies, which is fine (and better imo)
_policyInformation.NAP.version = "2022-11-11-001"

securityLevel = _policyInformation.NAP.securityLevel

-- set no-rules-active to be the same as balanced-ips for NAP configs
if _policyInformation.NAP.id == "no-rules-active-NAP" then
   securityLevel = 20
end


-- all policies
include('baseconfig.lua')
detection.global_default_rule_state = false

-- drop all packets with invalid checksums because they are invalid and will not be accepted
-- by the destination host, anyway.
network.checksum_drop = "all"

ssl.trust_servers = true

port_scan = nil

stream_ip.policy = 'windows'
stream_tcp.policy = 'windows'

ftp_client.bounce = true
ftp_client.telnet_cmds = true

if cip ~= nil then
   cip.embedded_cip_path = '0x2 0x36'
end

-- disable UTF8 normalization, which converts two- and three-byte UTF8 characters in the URI to '|FF|'
http_inspect.utf8 = false

-- The snort_ml global config (snort_ml_engine) needs to be present for all policies, then the individual
-- NAP policies specifies its particular config using the snort_ml table
if TALOS.functions.minsnortver(3,1,79,1,0) then
   if snort_ml_engine == nil then
      snort_ml_engine = { http_param_model = TALOS.functions.script_path() .. "../../extras/snort_ml/http_param.model"; }
   end
end

-- just connectivity
if securityLevel == 10 then

   http_inspect.unzip = false

end


-- connectivity and balanced (and no-rules-active)
if securityLevel <= 20 then

   http_inspect.request_depth = 1000
   http_inspect.response_depth = 1000

end


-- security and max-detect
if securityLevel >= 30 then

   -- enable_inspector won't overwrite configs if an inspector is already enabled
   TALOS.functions.enable_inspector("sip", 30)
   TALOS.functions.enable_inspector("modbus", 30)

   -- this is temporary for accounting for a bug in enable_signature
   if MISSING_FI_ES_FIX == true then
      file_id.enable_signature = true
   end

   http_inspect.decompress_swf = true
   http_inspect.decompress_pdf = true
   http_inspect.decompress_zip = true
   http_inspect.percent_u = true

   -- This if() statement is negated because we want to use old normalizer if the new normalizer is not available
   if (not (TALOS.functions.minsnortver(3,1,28,0,0) or (TALOS.functions.minsnortver(3,1,21,1,120) and TALOS.functions.stopsnortver(3,1,22,0,0)))) then
      -- old style javascript normalizer, in file_data buffer
      http_inspect.normalize_javascript = true
   end

   imap.b64_decode_depth = -1
   imap.bitenc_decode_depth = -1
   imap.qp_decode_depth = -1
   imap.uu_decode_depth = -1
   imap.decompress_pdf = true
   imap.decompress_swf = true
   imap.decompress_zip = true
   
   pop.b64_decode_depth = -1
   pop.bitenc_decode_depth = -1
   pop.qp_decode_depth = -1
   pop.uu_decode_depth = -1
   pop.decompress_pdf = true
   pop.decompress_swf = true
   pop.decompress_zip = true
   
   smtp.b64_decode_depth = -1
   smtp.bitenc_decode_depth = -1
   smtp.qp_decode_depth = -1
   smtp.uu_decode_depth = -1
   smtp.decompress_pdf = true
   smtp.decompress_swf = true
   smtp.decompress_zip = true
   
   telnet.check_encrypted = true
   telnet.normalize = true

   ftp_server.check_encrypted = true
   ftp_server.encrypted_traffic = true -- this is actually for a bug; should be handled by check_encrypted

   -- Turn on multiple alerts for dce events (lower policies will still block traffic;
   -- this is essentially just a reporting item)
   dce_smb.limit_alerts = false
   dce_tcp.limit_alerts = false
   dce_udp.limit_alerts = false
   
end


-- just max-detect
if securityLevel == 40 then

   -- disable latency enforcement for max-detect
   latency = nil

   -- log more stuff
   event_queue.max_queue = 15
   event_queue.log = 15

   -- enable BO only in max-d
   if back_orifice == nil then
      back_orifice = { }
   end

   -- ssl.trust_servers is false by default, but above we set it to true for all policies
   ssl.trust_servers = false
   search_engine.queue_limit = 0;
   -- detect_raw_tcp makes snort 3 process raw packets like snort 2 does, which can allow
   -- poorly written rules to alert, but then you lose perf and FP resistance of Snort 3 buffers
   -- search_engine.detect_raw_tcp = true

   if MISSING_SCRIPT_DETECTION == nil then
      http_inspect.script_detection = true
   end

   -- Enable snort_ml analysis
   if TALOS.functions.minsnortver(3,1,79,1,0) then
      if snort_ml == nil then
         snort_ml = {}
      end
   end

end

-- Open Source lightSPD package doesn't include an Snort_ML model so we need to clear out the configurations
snort_ml_engine = nil
snort_ml = nil  
