if _policyInformation == nil then
   _policyInformation = { }
end

_policyInformation.IPS =
{
   id = "no-rules-active-IPS",
   version = "2021-06-03-001",
   name = "No Rules Active",
   description = "This policy is a basic policy that configures typical preprocessor settings but does not have any rules or built-in alerts enabled.",
   snort2equivalent = "no-rules-active",
   securityLevel = 1, -- later, we're going to give this same NAP config as balanced-ips
   displayOrder = 50,
   isSnort2LegacyPolicy = true
}

rulestatesFileName = "rulestates-no-rules-active.states"

include('../../common/load_ips.lua')

