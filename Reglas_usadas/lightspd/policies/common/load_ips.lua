--io.stderr:write("load_ips.lua loaded\n")
--
-- Loads components of the ips table to create the IPS policy
-- 
-- Provide rulestatesFileName, which is the name used for the rule states, and
-- ruleDirs, which is an array of strings of paths to where to find rules (all types)
--
-- ruleDirs is always required.  rulestatesFileName is only required if loading rule states
--
-- If you don't want to load the rule states, or don't want to load the rule files,
-- set DO_NOT_LOAD_RULE_STATES or DO_NOT_LOAD_RULES to any value prior to inclusion
--

include('snort_variables.lua')
include('snort_defaults.lua')
include('file_magic.lua')
include('talos_functions.lua')


-- Where to find our rules (note this overwrites the contents of ruleDirs.lua, currently)
ruleDirs = {
   "../../rules/3.0.0.0",
   "../../builtins/3.0.0.0-0",
   "../../modules/stubs"
}

-- Rules that require a minimum snort version of 3.1.35.0
if TALOS.functions.minsnortver(3,1,35,0,0) then
   table.insert(ruleDirs, "../../rules/3.1.35.0")
end


-- So file_type rules work
if file_id == nil then
   file_id = { }
end

if TALOS.functions.minsnortver(3,1,35,0,0) then
   if file_id.rules_file == nil then 
      file_id.rules_file = 'file_magic.rules'
   end
else
   if file_id.file_rules == nil then
      file_id.file_rules = file_magic
   end
end

-- so rules load
if references == nil then
   references = default_references
end

-- so rule load
if classifications == nil then
   classifications = default_classifications
end

if ruleDirs == nil then
   print("load_ips: ruleDirs == nil")
   os.exit(-1)
end

if ips == nil then
   ips = { }
end

if DO_NOT_LOAD_RULES == nil then

   if ips.rules == nil then
      ips.rules = ""
   end

else

   -- Ensure Talos rule states are not loaded if we haven't loaded Talos rules
   DO_NOT_LOAD_RULE_STATES = true

end

if DO_NOT_LOAD_RULE_STATES == nil then

   if rulestatesFileName == nil then
      print("load_ips: rulestatesFileName == nil")
      os.exit(-1)
   end

   if ips.states == nil then
      ips.states = ""
   end
end

for i,v in ipairs(ruleDirs) do

   if DO_NOT_LOAD_RULE_STATES == nil then
      ips.states = ips.states .. "include " .. v .. "/" .. rulestatesFileName .. "\n"

      -- disable problematic rule(s) on older versions of snort
      -- rule states stay with whatever is last in the list, so even if a rule is enabled previously,
      -- having a disable here overrides it
      if(TALOS.functions.stopsnortver(3,0,3,0,6)) then -- 3.0.3-6
         ips.states = ips.states .. "alert (gid:1; sid:39905; enable:no;)\n"
         ips.states = ips.states .. "alert (gid:1; sid:21164; enable:no;)\n"
      end
   end

   if DO_NOT_LOAD_RULES == nil then
      if string.find(v, "builtins") then
         ips.rules = ips.rules .. "include " .. v .. "/builtins.rules\n"
      else
         ips.rules = ips.rules .. "include " .. v .. "/includes.rules\n"
      end
   end
end

-- Sensitive Data rules are a somewhat special case
-- Talos doesn't enable them by default so we don't need to worry about rulestates files
-- New sd_pattern capabilities were added after initial release, so although it was technically
-- available in 3.0.0.0, we're setting a later start version.
-- And it's only available if hyperscan is available, so we have to check for that capability
if DO_NOT_LOAD_RULES == nil then
   if TALOS.functions.minsnortver(3,1,46,0,0) then
      if SNORT_DEP_VERSIONS["HYPERSCAN"] ~= nil then
         ips.rules = ips.rules .. "include ../../policies/common/sensitive-data.rules\n"
      end
   end
end


