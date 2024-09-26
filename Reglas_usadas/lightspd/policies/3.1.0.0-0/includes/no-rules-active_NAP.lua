if _policyInformation == nil then
   _policyInformation = { }
end

_policyInformation.NAP =
{
   id = "no-rules-active-NAP",
   version = "2021-06-03-001",
   name = "No Rules Active",
   description = "This policy is a basic policy that configures typical preprocessor settings but does not have any rules or built-in alerts enabled.",
   snort2equivalent = "no-rules-active",
   securityLevel = 1, -- later, we're going to give this same NAP config as balanced-ips
   displayOrder = 50,
   isSnort2LegacyPolicy = true
}

include("../../common/policy_logic.lua")

