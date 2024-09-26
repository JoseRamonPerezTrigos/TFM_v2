if _policyInformation == nil then
   _policyInformation = { }
end

_policyInformation.NAP =
{
   id = "security-ips-NAP",
   version = "2021-06-03-001",
   name = "Security Over Connectivity",
   description = "This policy places an emphasis on security, at the possible expense of network connectivity and throughput.  Traffic is inspected more deeply, more rules are evaluated, and both false positives and increased latency are expected but within reason.",
   snort2equivalent = "security-over-connectivity",
   securityLevel = 30,
   displayOrder = 20,
   isSnort2LegacyPolicy = true
}

include("../../common/policy_logic.lua")

