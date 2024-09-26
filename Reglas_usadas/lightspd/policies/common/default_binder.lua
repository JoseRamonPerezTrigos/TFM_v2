--io.stderr:write("default_binder.lua loaded\n")

default_binder =
{
    -- port bindings required for protocols without wizard support
    { when = { proto = 'udp', ports = '53', role = 'server' },  use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '53', role = 'server' },  use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '111', role = 'server' }, use = { type = 'rpc_decode' } },
    { when = { proto = 'tcp', ports = '502', role = 'server' }, use = { type = 'modbus' } },
    { when = { proto = 'tcp', ports = '2123 2152 3386', role = 'server' }, use = { type = 'gtp_inspect' } },
    { when = { proto = 'udp', ports = '2222', role = 'server' }, use = { type = 'cip' } },
    { when = { proto = 'tcp', ports = '44818', role = 'server' }, use = { type = 'cip' } },
    { when = { proto = 'tcp', ports = '2404', role='server' }, use = { type = 'iec104' } },
    { when = { proto = 'tcp', service = 'dcerpc' }, use = { type = 'dce_tcp' } },
    { when = { proto = 'udp', service = 'dcerpc' }, use = { type = 'dce_udp' } },
    { when = { proto = 'udp', service = 'netflow' }, use = { type = 'netflow' } },

    { when = { service = 'netbios-ssn' },      use = { type = 'dce_smb' } },
    { when = { service = 'dce_http_server' },  use = { type = 'dce_http_server' } },
    { when = { service = 'dce_http_proxy' },   use = { type = 'dce_http_proxy' } },

    { when = { service = 'dnp3' },             use = { type = 'dnp3' } },
    { when = { service = 'dns' },              use = { type = 'dns' } },
    { when = { service = 'ftp' },              use = { type = 'ftp_server' } },
    { when = { service = 'ftp-data' },         use = { type = 'ftp_data' } },
    { when = { service = 'gtp' },              use = { type = 'gtp_inspect' } },
    { when = { service = 'imap' },             use = { type = 'imap' } },
    { when = { service = 'http' },             use = { type = 'http_inspect' } },
    { when = { service = 'http2' },            use = { type = 'http2_inspect' } },
    { when = { service = 'iec104' },           use = { type = 'iec104' } },
    { when = { service = 'mms' },              use = { type = 'mms' } },
    { when = { service = 'modbus' },           use = { type = 'modbus' } },
    { when = { service = 's7commplus' },       use = { type = 's7commplus' } },
    { when = { service = 'cip' },              use = { type = 'cip' } },
    { when = { service = 'pop3' },             use = { type = 'pop' } },
    { when = { service = 'ssh' },              use = { type = 'ssh' } },
    { when = { service = 'sip' },              use = { type = 'sip' } },
    { when = { service = 'smtp' },             use = { type = 'smtp' } },
    { when = { service = 'ssl' },              use = { type = 'ssl' } },
    { when = { service = 'sunrpc' },           use = { type = 'rpc_decode' } },
    { when = { service = 'telnet' },           use = { type = 'telnet' } },

    { use = { type = 'wizard' } }
}

local function getsnortver()

   if(SNORT_VERSION == nil) then
      return 0, 0, 0, 0, 0
   end 

   local snortver = {}
   for digits in string.gmatch(SNORT_VERSION, "%d+") do
      table.insert(snortver, tonumber(digits))
   end

   -- We don't want this unless 3.1.0.0 or later
   if(snortver[1] == 3 and snortver[2] == 0) then
      return 0, 0, 0, 0, 0
   end

   -- If there's no build number, set it to 0
   if(snortver[5] == nil) then
      snortver[5] = 0
   end

   return snortver[1], snortver[2], snortver[3], snortver[4], snortver[5]
end


MAJ, MIN, PAT, SUB, BUI = getsnortver()
--io.stderr:write("snortver: " .. MAJ .. "." .. MIN .. "." .. PAT .. "." .. SUB .. "-" .. BUI .. "\n")
-- Note doing this actually puts the entry out of order in default_binder, but when add_binder_entries() is
-- called to actually put this information into the real binder, it'll be in the proper place.
-- s7commplus wizard replaces the binder entry in:
-- 3.1.44.0 and later (7.4)
-- 3.1.36.1-85+ (7.3)
-- 3.1.21.300-3+ (7.2.3)
if not
   ((MAJ == 3) and
      (MIN > 1) or
         ((MIN == 1) and
            ((PAT >= 44) or
             (PAT == 36 and SUB == 1 and BUI >= 85) or
             (PAT == 21 and SUB == 300 and BUI >= 3)
            )
         )
   )
then
      table.insert(default_binder, { when = { proto = 'tcp', ports = '102', role = 'server' }, use = { type = 's7commplus' } })
end

