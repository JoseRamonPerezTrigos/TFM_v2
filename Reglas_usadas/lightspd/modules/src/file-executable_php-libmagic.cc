//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
//
// This file may contain proprietary rules that were created, tested and
// certified by Sourcefire, Inc. (the "VRT Certified Rules") as well as
// rules that were created by Sourcefire and other third parties and
// distributed under the GNU General Public License (the "GPL Rules").
// The VRT Certified Rules contained in this file are the property of
// Sourcefire, Inc. Copyright 2005 Sourcefire, Inc. All Rights Reserved.
// The GPL Rules created by Sourcefire, Inc. are the property of
// Sourcefire, Inc. Copyright 2002-2005 Sourcefire, Inc. All Rights
// Reserved. All other GPL Rules are owned and copyrighted by their
// respective owners (please see www.snort.org/contributors for a list
// of owners and their respective copyrights). In order to determine what
// rules are VRT Certified Rules or GPL Rules, please refer to the VRT
// Certified Rules License Agreement.
//--------------------------------------------------------------------------
// file-executable_php-libmagic.cc author Brandon Stultz <brastult@cisco.com>

#include "framework/cursor.h"
#include "framework/so_rule.h"
#include "main/snort_types.h"
#include "protocols/packet.h"
#include "util_read.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_38347 = R"[Snort_SO_Rule](
alert file (
	msg:"FILE-EXECUTABLE PHP libmagic PE out of bounds memory access attempt";
	soid:38347;
	file_data;
	content:"MZ";
	byte_jump:4,58,relative,little,post_offset -64;
	content:"PE|00 00|",within 4;
	content:".rsrc|00 00 00|";
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2014-2270;
	classtype:attempted-dos;
	gid:3; sid:38347; rev:2;
)
)[Snort_SO_Rule]";

static const unsigned rule_38347_len = 0;

static const char* rule_300947 = R"[Snort_SO_Rule](
alert http (
	msg:"FILE-EXECUTABLE PHP libmagic PE out of bounds memory access attempt";
	soid:300947;
	http_client_body;
	content:"MZ";
	byte_jump:4,58,relative,little,post_offset -64;
	content:"PE|00 00|",within 4;
	content:".rsrc|00 00 00|";
	so:eval;
	metadata:policy max-detect-ips drop;
	reference:cve,2014-2270;
	classtype:attempted-dos;
	gid:3; sid:300947; rev:1;
)
)[Snort_SO_Rule]";

static const unsigned rule_300947_len = 0;

static IpsOption::EvalStatus DetectLibmagicOOBRead(Cursor& c)
{
    const uint8_t *cursor_normal = c.start(),
                  *end_of_buffer = c.endo();

    uint32_t raw_size, raw_addr;

    // skip VirtualSize (4 bytes) & VirtualAddr (4 bytes)
    cursor_normal += 8;

    // read RawSize (4 bytes) & RawAddr (4 bytes)
    if(cursor_normal + 8 > end_of_buffer)
        return IpsOption::NO_MATCH;

    raw_size = read_little_32_inc(cursor_normal);
    raw_addr = read_little_32(cursor_normal);

    DEBUG_SO(fprintf(stderr,"PE RawSize 0x%08X RawAddr 0x%08X\n",raw_size,raw_addr);)

    if(raw_size + raw_addr > 0x7fffffff)
        return IpsOption::MATCH;

    return IpsOption::NO_MATCH;
} 

static IpsOption::EvalStatus rule_38347_eval(void*, Cursor& c, Packet*)
{
    return DetectLibmagicOOBRead(c);
}

static SoEvalFunc rule_38347_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_38347_eval;
}

static const SoApi so_38347 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        2, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "38347", // name
        "FILE-EXECUTABLE PHP libmagic PE out of bounds memory access attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_38347,
    rule_38347_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_38347_ctor,    // ctor
    nullptr  // dtor
};

static IpsOption::EvalStatus rule_300947_eval(void*, Cursor& c, Packet*)
{
    return DetectLibmagicOOBRead(c);
}

static SoEvalFunc rule_300947_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_300947_eval;
}

static const SoApi so_300947 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        1, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "300947", // name
        "FILE-EXECUTABLE PHP libmagic PE out of bounds memory access attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_300947,
    rule_300947_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_300947_ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_38347 = &so_38347.base;
const BaseApi* pso_300947 = &so_300947.base;
