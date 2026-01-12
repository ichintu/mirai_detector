module Mirai;

@load base/frameworks/notice

export {
    redef enum Notice::Type += {
        ## Mirai scan detection notice.
        Mirai_Scan
    };
}

redef detect_filtered_trace = F;

function addr_to_int(ip: addr): count
{
    if (!is_v4_addr(ip)) {
        print fmt("DEBUG: Invalid IPv4 address: %s", ip);
        return 0;
    }
    local parts: vector of count;
    local ip_str = fmt("%s", ip);
    local str_parts = split_string(ip_str, /\./);
    if (|str_parts| != 4) {
        print fmt("DEBUG: Failed to parse IP %s: %s", ip, str_parts);
        return 0;
    }
    parts = vector(to_count(str_parts[0]), to_count(str_parts[1]),
                   to_count(str_parts[2]), to_count(str_parts[3]));
    return parts[0] * 16777216 + parts[1] * 65536 + parts[2] * 256 + parts[3];
}

event new_packet(c: connection, p: pkt_hdr)
{
    if ( ! p?$tcp ) {
        return;
    }

    local tcp_flags: count = p$tcp$flags;
    local flags: string = "";
    if ( tcp_flags & 0x20 != 0 ) flags += "U";
    if ( tcp_flags & 0x10 != 0 ) flags += "A";
    if ( tcp_flags & 0x08 != 0 ) flags += "P";
    if ( tcp_flags & 0x04 != 0 ) flags += "R";
    if ( tcp_flags & 0x02 != 0 ) flags += "S";
    if ( tcp_flags & 0x01 != 0 ) flags += "F";

    # Only check SYN packets (per your preference)
    if (flags != "S") {
        return;
    }

    local src: addr = p?$ip ? p$ip$src : p$ip6$src;
    local dst: addr = p?$ip ? p$ip$dst : p$ip6$dst;
    local is_orig: bool = (src == c$id$orig_h && dst == c$id$resp_h);
    # if ( ! is_orig ) {
    #     return;
    # }

    local dst_int = addr_to_int(c$id$resp_h);
    local raw_seq: count = p$tcp$seq;

    # Debug: Log every SYN packet processed
    # print fmt("DEBUG: Processing SYN packet: %s -> %s:%d, seq=%d, dst_int=%d, is_orig=%s",
    #           c$id$orig_h, c$id$resp_h, c$id$resp_p, raw_seq, dst_int, is_orig);

    # Compare sequence number directly from packet header
    if (raw_seq == dst_int) {
        # print fmt("DEBUG: Mirai match found: %s -> %s:%d, seq=%d, dst_int=%d",
        #           c$id$orig_h, c$id$resp_h, c$id$resp_p, raw_seq, dst_int);
        NOTICE([$note=Mirai_Scan,
                $msg=fmt("Mirai scan detected: SEQ (%d) matches DST IP value (%d) from %s to %s:%d",
                         raw_seq, dst_int, c$id$orig_h, c$id$resp_h, c$id$resp_p),
                $conn=c,
                $identifier=fmt("%s<->%s:%d", c$id$orig_h, c$id$resp_h, c$id$resp_p),
                $suppress_for=1 hr]);
    }
}
