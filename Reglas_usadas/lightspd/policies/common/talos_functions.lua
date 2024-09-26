--io.stderr:write("talos_functions.lua loaded\n")
include('default_binder.lua')

-- Do not change the threat_hunting_telemetry_gid until reload capability is added
-- to sfunified2_logger, ticket NGFW-240.
threat_hunting_telemetry_gid = 6 -- do not change

if TALOS == nil then
   TALOS = {}
end

if TALOS.functions == nil then
   TALOS.functions = {}
end

TALOS.functions.script_path = function()
   str = path_top()
   return str:match("(.*/)") or "./"
end

TALOS.functions.push_array = function(existing, new)

   existing = existing or {}

   if new then
      for k,v in pairs(new) do
         table.insert(existing, v)
      end
   end

   return existing
end


TALOS.functions.binder_entry_exists = function(name)

   for i, v in pairs (binder) do
      if v.use ~= nil then
         if v.use.type == name then
            --print("Found binder entry for " .. name)
            return true
         end
      end
   end

   return false
end

TALOS.functions.add_binder_entries = function()

   -- if no binder currently exists, create it now
   if binder == nil then
      binder = {}
   end

   -- we split them out to maintain heirarchy -- policies, ports, services, everything else
   -- for existing binders, we maintain order (within those groups), and add our
   -- new stuff to the end of the respective category
   policy_bindings = {}
   port_bindings = {}
   service_bindings = {}
   other_bindings = {}  -- everything else

   -- Copy existing bindings that are in use to the new binder
   for i, v in pairs (binder) do

      if v.use == nil or v.use.type == nil then -- oddballs
         table.insert(other_bindings, v)
      elseif v.use.inspection_policy ~= nil or v.use.ips_policy ~= nil then -- policies
         table.insert(policy_bindings, v)
      elseif env[v.use.type] ~= nil then -- inspector is loaded, so keep existing binding
         if v.when == nil then
            table.insert(other_bindings, v)
         else
            if v.when.ports ~= nil then
               table.insert(port_bindings, v)
            elseif v.when.service ~= nil then
               table.insert(service_bindings, v)
            else
               table.insert(other_bindings, v) -- catch-all, just in case
            end
         end
      end
   end

   -- Copy default bindings for modules in use but without a binder
   for i, v in pairs (default_binder) do
       if v.use ~= nil then
          if env[v.use.type] ~= nil then

             if not TALOS.functions.binder_entry_exists(v.use.type) then
                -- print("Adding default binder for " .. v.use.type)
               if v.when == nil then
                  table.insert(other_bindings, v)
               else
                  if v.when.ports ~= nil then
                     table.insert(port_bindings, v)
                  elseif v.when.service ~= nil then
                     table.insert(service_bindings, v)
                  else
                     table.insert(other_bindings, v) -- catch-all, just in case
                  end
               end
             end
          end
       end
   end

   -- empty the current binder to rebuild it
   binder = {}
   for i, v in pairs (policy_bindings) do
      table.insert(binder, v)
   end
   for i, v in pairs (port_bindings) do
      table.insert(binder, v)
   end
   for i, v in pairs (service_bindings) do
      table.insert(binder, v)
   end
   for i, v in pairs (other_bindings) do
      table.insert(binder, v)
   end
end


TALOS.functions.enable_inspector = function(inspector_name, seclevel)

   env = getfenv()

   -- default seclevel to sane default (same as in NAP config)
   if seclevel == nil then
      if securityLevel ~= nil then
         seclevel = securityLevel
      else
         seclevel = 20 -- fall back to balanced security and connectivity if necessary
      end
   end

   -- Don't reconfigure with defaults if it's already configured
   if env[inspector_name] == nil then
      -- ultimately, this will set a configuration based upon the security level
      env[inspector_name] = {}

      if inspector_name == "cip" then
         cip.embedded_cip_path = '0x2 0x36'
      end

      if inspector_name == "gtp_inspect" then
         gtp_inspect = default_gtp
      end
   end

   TALOS.functions.add_binder_entries()

   return true
end


TALOS.functions.getsnortver = function()
   if(SNORT_VERSION == nil or SNORT_VERSION == "") then
      -- SNORT_VERSION wasn't introduced until 3.0.3-3 (Oct 2020)
      -- Those older versions will need to use old-style conf directories
      return 0, 0, 0, 0, 0
   end

   sublevel = SNORT_SUBLEVEL_VERSION
   if sublevel == nil then
      -- three-digit snort version (pre 3.1.0.0)
      sublevel = 0
   end

   build = 0
   dash = string.find(SNORT_VERSION, "-")
   if dash ~= nil then
      build = tonumber(string.sub(SNORT_VERSION, dash + 1))
   end

   return SNORT_MAJOR_VERSION, SNORT_MINOR_VERSION, SNORT_PATCH_VERSION, sublevel, build
end

TALOS.functions.minsnortver = function(cmajor, cminor, cpatch, csublevel, cbuild)
   -- When calling, convert three-digit snort versions and build numbers that are not set
   -- to full four digit plus build number.  ie 3.0.0 would be given as 3.0.0.0-0
   -- Note that snort version is not available prior to 3.0.3-6 and will come back
   -- from getsnortver() as 0.0.0.0-0 but that's long ago so doesn't matter
   smajor, sminor, spatch, ssublevel, sbuild = TALOS.functions.getsnortver()

   --print("minsnortver check: " .. cmajor .. "." .. cminor .. "." .. cpatch .. "." .. csublevel .. "-" .. cbuild)
   --print("minsnortver snort: " .. smajor .. "." .. sminor .. "." .. spatch .. "." .. ssublevel .. "-" .. sbuild)

   if smajor > cmajor then
      return true
   end
   if smajor < cmajor then
      return false
   end

   if sminor > cminor then
      return true
   end
   if sminor < cminor then
      return false
   end

   if spatch > cpatch then
      return true
   end
   if spatch < cpatch then
      return false
   end

   if ssublevel > csublevel then
      return true
   end
   if ssublevel < csublevel then
      return false
   end

   if sbuild >= cbuild then
      return true
   end
   if sbuild < cbuild then
      return false
   end

   print("minsortver can't get here")
   os.exit()
end

TALOS.functions.maxsnortver = function(cmajor, cminor, cpatch, csublevel, cbuild)
   -- stopsnortver is similar to maxsnortver, except that it returns false if the
   -- current snortver matches what you are checking for.  This is useful for when
   -- you want a feature to be enabled for versions UP TO BUT NOT INCLUDING the
   -- specified version.
   --
   -- returns TRUE if running snort version is less than or equal to the check version INCLUSIVE
   --
   -- When calling, convert three-digit snort versions and build numbers that are not set
   -- to full four digit plus build number.  ie 3.0.0 would be given as 3.0.0.0-0
   -- Note that snort version is not available prior to 3.0.3-6 and will come back
   -- from getsnortver() as 0.0.0.0-0 but that's long ago so doesn't matter.  Also,
   -- for NAP configuration, those old versions shouldn't touch this function.
   smajor, sminor, spatch, ssublevel, sbuild = TALOS.functions.getsnortver()

   if smajor < cmajor then
      return true 
   end
   if smajor > cmajor then
      return false
   end

   if sminor < cminor then
      return true
   end
   if sminor > cminor then
      return false
   end

   if spatch < cpatch then
      return true
   end
   if spatch > cpatch then
      return false
   end

   if ssublevel < csublevel then
      return true
   end
   if ssublevel > csublevel then
      return false
   end

   if sbuild <= cbuild then
      return true
   end
   if sbuild > cbuild then
      return false
   end

   -- can't get here
   print("maxsnortver can't get here")
   os.exit()
end

TALOS.functions.stopsnortver = function(cmajor, cminor, cpatch, csublevel, cbuild)
   -- stopsnortver is similar to maxsnortver, except that it returns false if the
   -- current snortver matches what you are checking for.  This is useful for when
   -- you want a feature to be enabled for versions UP TO BUT NOT INCLUDING the
   -- specified version.
   --
   -- returns TRUE if running snort version is less than the check version, NOT inclusive
   --
   -- When calling, convert three-digit snort versions and build numbers that are not set
   -- to full four digit plus build number.  ie 3.0.0 would be given as 3.0.0.0-0
   -- Note that snort version is not available prior to 3.0.3-6 and will come back
   -- from getsnortver() as 0.0.0.0-0 but that's long ago so doesn't matter.  Also,
   -- for NAP configuration, those old versions shouldn't touch this function.
   smajor, sminor, spatch, ssublevel, sbuild = TALOS.functions.getsnortver()

   --print("stopsnortver check: " .. cmajor .. "." .. cminor .. "." .. cpatch .. "." .. csublevel .. "-" .. cbuild)
   --print("stopsnortver snort: " .. smajor .. "." .. sminor .. "." .. spatch .. "." .. ssublevel .. "-" .. sbuild)

   if smajor < cmajor then
      return true 
   end
   if smajor > cmajor then
      return false
   end

   if sminor < cminor then
      return true
   end
   if sminor > cminor then
      return false
   end

   if spatch < cpatch then
      return true
   end
   if spatch > cpatch then
      return false
   end

   if ssublevel < csublevel then
      return true
   end
   if ssublevel > csublevel then
      return false
   end

   if sbuild < cbuild then
      return true
   end
   if sbuild >= cbuild then
      return false
   end

   -- can't get here
   print("stopsnortver can't get here")
   os.exit()
end

TALOS.functions.issnortver = function(cmajor, cminor, cpatch, csublevel, cbuild)
   -- When calling, convert three-digit snort versions and build numbers that are not set
   -- to full four digit plus build number.  ie 3.0.0 would be given as 3.0.0.0-0
   -- Note that snort version is not available prior to 3.0.3-6 and will come back
   -- from getsnortver() as 0.0.0.0-0 but that's long ago so doesn't matter.  Also,
   -- for NAP configuration, those old versions shouldn't touch this function.
   smajor, sminor, spatch, ssublevel, sbuild = TALOS.functions.getsnortver()

   return ((cmajor == smajor) and (cminor == sminor) and (cpatch == spatch) and (csublevel == ssublevel) and (cbuild == sbuild))

end


TALOS.functions.get_threat_hunting_telemetry_gid = function()
   -- simply returns the gid used for Talos Threat Hunting Telemetry Rules

   return threat_hunting_telemetry_gid -- threat hunting gid, gid used in threat hunting rules

end


TALOS.functions.enable_threat_hunting_telemetry = function()
   -- Call to enable rules that Talos uses for "hunting."

   -- Verify our minimum snort version for support of this feature
   if (not TALOS.functions.minsnortver(3,1,70,0,170)) then
      return false
   end

   -- Add the appropriate supported snort versions to our list
   th_versions = {}
   table.insert(th_versions, "3.0.0.0") -- currently everything is in 3.0.0.0

   -- Because we can't test for the presence of a file in lua, at least not in a way that would be
   -- deemed "safe" from within our environment, we're going to blindly include a "silent rules include file"
   -- here, then manually/selectively add files to that include file outside of this process.
   if ips == nil then
      ips = {}
   end

   if DO_NOT_LOAD_RULES == nil then
      if ips.rules == nil then
         ips.rules = ""
      end
   
      -- Load all of the rules, both plaintext and SO stubs, which are in the same file(s)
      for i, v in pairs (th_versions) do
         ips.rules = ips.rules .. "include ../../extras/threat-hunting/" .. v .. "/threat-hunting.rules\n"
      end
   end

   -- Add rulestates tables, according to current rules policy
   if ips.states == nil then
      ips.states = ""
   end

   -- Load the rulestates file appropriate to our IPS policy
   if _policyInformation == nil then
      print("_policyInformation is nil")
      return false
   end

   if _policyInformation.IPS == nil then
      print("_policyInformation.IPS is nil")
      return false
   end

   if DO_NOT_LOAD_RULE_STATES == nil then
      if rulestatesFileName == nil then
         print("load_ips: rulestatesFileName == nil")
         os.exit(-1)
      end
   
      if ips.states == nil then
         ips.states = ""
      end

      for i, v in pairs (th_versions) do
         ips.states = ips.states .. "include ../../extras/threat-hunting/" .. v .. "/" .. rulestatesFileName .. "\n"
      end
   end

   return true
end
