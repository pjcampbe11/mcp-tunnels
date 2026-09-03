##! mcp-tunnels :: flag MCP protocol headers in cleartext HTTP.
##!
##! Only works on UNENCRYPTED HTTP — useful behind a TLS-terminating proxy, on
##! an internal segment, or in the lab. It is the cleanest way to prove to a
##! stakeholder that the tool name is on the wire.
##!
##! Zeek uppercases header names in http_header.

@load base/protocols/http

export {
    redef enum Notice::Type += {
        MCP::Request_Observed,
        MCP::Tool_Invoked,
    };
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if ( ! is_orig ) return;

    if ( name == "MCP-PROTOCOL-VERSION" )
        NOTICE([$note=MCP::Request_Observed,
                $msg=fmt("MCP request to %s:%s version=%s",
                         c$id$resp_h, c$id$resp_p, value),
                $conn=c]);

    if ( name == "MCP-NAME" )
        NOTICE([$note=MCP::Tool_Invoked,
                $msg=fmt("MCP tool invoked: %s", value),
                $conn=c]);
}
