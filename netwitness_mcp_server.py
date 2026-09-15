#!/usr/bin/env python3
"""
NetWitness MCP Server
=====================
Queries metadata from a NetWitness Concentrator/Broker and Incidents/Alerts data
from the Admin Server API. All tool outputs are returned as structured JSON.

Response envelope (every tool):
{
  "status":   "success" | "error",
  "tool":     "<tool_name>",
  "query":    { ...echoed inputs... },
  "data":     { ...tool-specific payload... } | null,
  "metadata": { ...counts, timing, pagination... },
  "error":    null | { "code": "...", "message": "..." }
}
"""
import os
import sys
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

import httpx
from mcp.server.fastmcp import FastMCP
from urllib.parse import quote_plus

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("netwitness-mcp-server")

# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------
mcp = FastMCP("netwitness")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_URL          = os.environ.get("NETWITNESS_API_URL", "")
API_USERNAME     = os.environ.get("NETWITNESS_USERNAME", "")
API_PASSWORD     = os.environ.get("NETWITNESS_PASSWORD", "")
NW_ADMIN_URL     = os.environ.get("NW_ADMIN_URL", "")
NW_ADMIN_USERNAME = os.environ.get("NW_ADMIN_USERNAME", "")
NW_ADMIN_PASSWORD = os.environ.get("NW_ADMIN_PASSWORD", "")

DEFAULT_HTTP_TIMEOUT = 30.0
TOKEN_TTL_SECONDS    = 600  # cache JWT for 10 minutes

# ---------------------------------------------------------------------------
# Response helpers - guarantee a single, consistent JSON envelope
# ---------------------------------------------------------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _envelope(
    status: str,
    tool: str,
    query: Optional[dict] = None,
    data: Any = None,
    metadata: Optional[dict] = None,
    error: Optional[dict] = None,
) -> str:
    """Serialize a standard response envelope to a JSON string."""
    payload = {
        "status":   status,
        "tool":     tool,
        "query":    query or {},
        "data":     data,
        "metadata": metadata or {},
        "error":    error,
    }
    return json.dumps(payload, indent=2, default=str, ensure_ascii=False)


def _success(tool: str, data: Any, query: Optional[dict] = None,
             metadata: Optional[dict] = None) -> str:
    md = {"generated_at": _now_iso()}
    if metadata:
        md.update(metadata)
    return _envelope("success", tool, query=query, data=data, metadata=md)


def _error(tool: str, code: str, message: str, query: Optional[dict] = None,
           metadata: Optional[dict] = None) -> str:
    logger.error("Tool %s error [%s]: %s", tool, code, message)
    md = {"generated_at": _now_iso()}
    if metadata:
        md.update(metadata)
    return _envelope(
        "error", tool,
        query=query, data=None, metadata=md,
        error={"code": code, "message": message},
    )


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------
_VALID_UNITS = {"m": "minutes", "h": "hours", "d": "days"}


def parse_time_range(time_range: str) -> tuple[int, str]:
    """Parse strings like '30m', '1h', '2d' into (value, unit). Raises ValueError on bad input."""
    if not time_range or len(time_range) < 2:
        raise ValueError(f"time_range must look like '30m', '1h', '2d'; got {time_range!r}")
    unit = time_range[-1].lower()
    if unit not in _VALID_UNITS:
        raise ValueError(f"time_range unit must be one of m/h/d; got {unit!r}")
    try:
        value = int(time_range[:-1])
    except ValueError as exc:
        raise ValueError(f"time_range value must be an integer; got {time_range[:-1]!r}") from exc
    if value <= 0:
        raise ValueError(f"time_range value must be positive; got {value}")
    return value, unit


def calculate_start_time(time_range: str) -> tuple[str, str]:
    """Convert a NetWitness-style range (e.g. '2d', '1h', '30m') to ISO 8601 (start, end)."""
    value, unit = parse_time_range(time_range)
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    delta = timedelta(**{_VALID_UNITS[unit]: value})
    start_dt = now_utc - delta
    fmt = lambda d: d.isoformat().replace("+00:00", "Z")
    return fmt(start_dt), fmt(now_utc)


# ---------------------------------------------------------------------------
# Documentation constants (verbatim from upstream reference)
# ---------------------------------------------------------------------------
META_KEYS_DOC = """# NetWitness Meta Keys Reference

## Network
- ip.src, ip.dst: Source/destination IP addresses
- tcp.dstport, udp.dstport: TCP/UDP destination port numbers
- tcp.srcport, udp.srcport: TCP/UDP source port numbers
- service: Service identifier. 20 (FTPD),21 (FTP),22 (SSH),23 (TELNET),25 (SMTP),53 (DNS),67 (DHCP),69 (TFTP),80 (HTTP),88 (KERBEROS),110 (POP3),111 (SUNRPC),119 (NNTP),123 (NTP),135 (RPC),137 (NETBIOS),138 (NETBIOS-DGM),139 (SMB),143 (IMAP),161 (SNMP),179 (BGP),389 (LDAP),443 (SSL),465 (SMTPS),500 (ISAKMP),502 (MODBUS),520 (RIP),554 (RTSP),995 (POP3S),1024 (EXCHANGE),1080 (SOCKS),1122 (MSN IM),1344 (ICAP),1352 (NOTES),1433 (TDS),1521 (TNS),1533 (SAMETIME),1719 (H.323),1720 (RTP),1812 (RADIUS),1813 (RADIUS-ACCT),2000 (SKINNY),2040 (SOULSEEK),2049 (NFS),3270 (TN3270),3389 (RDP),3700 (DB2),5050 (YAHOO IM),5060 (SIP),5190 (AOL IM),5222 (Google Talk),5721 (Kaseya),5900 (VNC),5938 (TEAMVIEWER),6346 (GNUTELLA),6667 (IRC),6801 (Net2Phone),6881 (BITTORRENT),7001 (Oracle_T3),7310 (SCREENCONNECT),8000 (QQ),8002 (YCHAT),8019 (WEBMAIL),8082 (FIX),20000 (DNP3),49152 (JSON-RPC),51820 (WireGuard),1000000 (KERNEL),1000001 (USER),1000003 (SYSTEM),1000004 (AUTH),1000005 (LOGGER),1000006 (LPD),1000008 (UUCP),1000009 (SCHEDULE),1000010 (SECURITY),1000013 (AUDIT),1000014 (ALERT),1000015 (CLOCK)
- size, payload: Traffic volume metrics
- eth.src, eth.dst: Ethernet MAC addresses
- direction: direction of the traffic (lateral, inbound, outbound)
- ip.proto: IP protocol (udp,tcp,icmp,ipv6-icmp,hopopt,igmp,esp)
- tcp.flags.desc: TCP flag (ack,psh,syn,fin,rst,cwr,ece,urg,ns)
- streams: defines whether the session is unidirectional (1) or bidirectional (2)

## Session Info
- sessionid: Unique session identifier
- time: Session timestamp
- country.src, country.dst: Geographic source/destination
- latdec.src, latdec.dst, longdec.src, longdec.dst: GPS coordinates
- org.src, org.dst: source/destination organization who owns the source IP address

## HTTP meta keys
This section includes the meta keys that specifically apply to HTTP traffic.
- action - request method ('get', 'post', et al)
- ad.computer.src - host credential from 'NTLMSSP' authorization
- ad.domain.src - domain credential from 'NTLMSSP' authorization
- ad.username.src - user credential from 'NTLMSSP' authorization
- alias.host - request 'HOST:' header
- alias.ip - request 'HOST:' header if IPv4
- alias.ipv6 - request 'HOST:' header if IPv6
- attachment - filename submitted in a POST request
- client - request 'USER-AGENT:' header
- content - 'CONTENT-TYPE' header
- directory - request directory
- email - proxy client if email address
- error - response status code if not '2xx'
- extension - request filename extension
- filename - request filename
- language - languages from language headers
- orig_ip - IP address of proxy client
- password - password credential from 'Basic' authorization
- query - request querystring
- referer - request 'REFERER:' header
- result - (optional) HTTP response status message
- result.code - (optional) HTTP response status code
- server - response 'SERVER:' header
- service - '80'
- username - user credential from 'Basic' authorization

## TLS/SSL/HTTPS meta keys
This section includes the meta keys that specifically apply to SSL, TLS, HTTPS traffic.
- alias.host - service name indicator, if hostname
- alias.ip - service name indicator, if ipv4
- alias.ipv6 - service name indicator, if ipv6
- analysis.service - TLS/SSL characteristics of interest
- error - Alert message description
- service - '443'
- version - 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'
### analysis.service
This section includes specific meta values for the analysis.service meta key specific to TLS/SSL/HTTP. You must not use any values not explicitly mentioned.
- SSL certificate chain incomplete
- SSL certificate missing Issuer Organizational Name
- SSL certificate missing Subject Organizational Name
- SSL certificate no issuer
- SSL certificate no subject
- SSL certificate self-signed
- certificate anomalous expiration date
- certificate anomalous issued date
- certificate domain validation
- certificate expired
- certificate expired within last week
- certificate extended validation
- certificate individual validation
- certificate issued within last day
- certificate issued within last month
- certificate issued within last week
- certificate long expiration
- certificate organization validation

## Kerberos meta keys
This section includes the meta keys that specifically apply to Kerberos traffic.
- action - Kerberos commands
- ad.computer.dst - host to which user is attempting authentication
- ad.computer.src - client source host
- ad.domain.dst - domain to which user is attempting authentication
- ad.domain.src - client source domain
- ad.username.dst - user as which actions are performed
- ad.username.src - client user
- crypto - Kerberos cryptography suite used for session
- error - Kerberos errors
- service - '88'

## LDAP meta keys
This section includes the meta keys that specifically apply to LDAP traffic.
- action - LDAP protocol operation
- error - (optional) LDAP diagnostic messages if included in operational responses
- password - if simple authentication, password used to authenticate to the LDAP server
- result - (optional) meaning of non-zero result code from operational responses
- result.code - (optional) non-zero numeric result code from operational responses
- service - '389'
- username - name used to authenticate to the LDAP server

## SMB meta keys
This section includes the meta keys that specifically apply to SMB traffic.
- action - SMB or DCERPC operation
- ad.computer.dst - target host of authentication
- ad.computer.src - source host of authenticated user
- ad.domain.dst - target domain of authentication
- ad.domain.src - source domain of authenticated user
- ad.username.dst - authenticated as user
- ad.username.src - authenticated user
- alias.host - target host of operation if hostname
- alias.ip - target host of operation if IPv4
- alias.ipv6 - target host of operation if IPv6
- crypto - Kerberos crypto type used for authentication
- directory - path directory
- error - error response from server
- extension - filename extension
- filename - target of file operation
- password - password from Tree Connect operation
- service - '139'

## DCERPC meta keys
This section includes the meta keys that specifically apply to DCERPC traffic.
- action - dcerpc message type, operation, wmi command
- ad.computer.dst - authentication hostname
- ad.computer.src - authenticated hostname
- ad.domain.dst - authentication domain
- ad.domain.src - authenticated domain
- ad.username.dst - authentication username
- ad.username.src - authenticated username
- crypto - kerberos crypto type
- error - dcerpc error messages
- filename - endpoint UUID name
- query - wmi parameters
- service - '135'

## DNS meta keys
This section includes the meta keys that specifically apply to DNS traffic.
- alias.host - hostnames of requests / answers
- alias.ip - ipv4 addresses of requests / answers
- alias.ipv6 - ipv6 addresses of requests / answers
- analysis.service - dns characteristics of interest
- dns.querytype - type of record in the dns query
- dns.responsetype - type of record dns response
- dns.resptext - contents of dns txt records
- email - soa name
- error - dns errors
- service - '53'
### analysis.service
This section includes specific meta values for the analysis.service meta key specific to DNS. You must not use any values not explicitly mentioned.
- anomalous dns message
- anomalous or non-dns session on dns port
- dns answer for uncommon record class
- dns answer for unknown record class
- dns answer for unknown record type
- dns base36 txt record
- dns base64 txt record
- dns dynamic update
- dns experimental record type
- dns extremely large number of answers
- dns extremely low auth ttl
- dns extremely low ttl
- dns invalid a record
- dns invalid aaaa record
- dns invalid edns version
- dns invalid error code
- dns invalid option code
- dns invalid query type
- dns large answer
- dns large number of additional records
- dns large number of answers
- dns large number of authority records
- dns large number of queries
- dns long query
- dns low ttl
- dns obscure record type
- dns obsolete record type
- dns query contains answer records
- dns query contains authority records
- dns query for uncommon record class
- dns query for unknown record class
- dns query for unknown record type
- dns reserved record type
- dns single request response
- dns unnasigned record type
- dns unsolicited response records
- dns update for unknown record class
- dns update for unknown record type
- dns z reserved present
- hostname looks like ip address
- large session dns port
- large session dns service
- loopback resolution of non-local name
- outbound dns
- suspicious traffic port 53

## IMAP meta keys
This section includes the meta keys that specifically apply to IMAP traffic.
- action - IMAP command issued
- error - IMAP error
- password - password credential provided to server
- service - '143'
- username - user credential provided to server'

## MAIL meta keys
This section includes the meta keys that specifically apply to MAIL traffic.
- action - mail action performed: 'sendfrom, 'sendto', 'attach'
- alias.host - hostname values from x-originating-ip headers, received headers, and (optional) email addresses
- alias.ip - ipv4 values from x-originating-ip headers, received headers, and (optional) email addresses
- alias.ipv6 - ipv6 values from x-originating-ip headers, received headers, and (optional) email addresses
- attachment - filenames of email attachments
- client - values from x-mailer: headers
- content - 'mail', value of Content-Type headers within messages
- email - email address found within messages
- email.dst - (optional) message recipients
- email.src - (optional) message originators
- extension - extension from filenames of email attachments
- fullname - comment portion of addresses, typically a name
- fullname.dst - (optional) comment portion of recipient addresses
- fullname.src - (optional) comment portion of sender addresses
- subject - values from subject: headers

## SCCP meta keys
This section includes the meta keys that specifically apply to SCCP traffic.
- fullname - calling and called party names
- phone - calling and called party numbers
- service - '2000'

## QQ meta keys
This section includes the meta keys that specifically apply to QQ traffic.
- action - QQ command
- service - '8000'
- username - user credential provided to server

## RTMP meta keys
This section includes the meta keys that specifically apply to RTMP traffic.
- alias.host - target host of RTMP url if name
- alias.ip - target host of RTMP url if IPv4
- alias.ipv6 - target host of RTMP url if IPv6
- content - 'RTMPT' for RTMPT over HTTP
- directory - target directory of RTMP url
- extension - filename extension of RTMP url
- filename - target file of RTMP url
- query - querystring parameters of RTMP url
- service - '1935'

## SCREENCONNECT meta keys
This section includes the meta keys that specifically apply to SCREENCONNECT traffic.
- alias.host - connection destination host if hostname
- alias.ip - connection destination host if IPv4
- alias.ipv6 - connection destination host if IPv6
- service - '7310'

## SIP meta keys
This section includes the meta keys that specifically apply to SIP traffic.
- alias.host - target host if name
- alias.ip - target host if IPv4
- alias.ipv6 - target host if IPv6
- content - value of Content-Type header
- email - sender and recipient addresses
- error - value SIP error response
- fullname - sender and recipient names
- service - '5060'
- username - address from SIP request

## SNMP meta keys
This section includes the meta keys that specifically apply to SNMP traffic.
- action - SNMP PDU Operation type
- error - PDU error status if non-zero
- password - SNMP community string
- service - '161'

## NFS meta keys
This section includes the meta keys that specifically apply to NFS traffic.
- action - NFS command
- alias.host - target host of NFS command if name
- alias.ip - target host of NFS command if IPv4
- alias.ipv6 - target host of NFS command if IPv6
- directory - target directory of NFS command
- error - NFS errors
- extension - filename extension
- filename - target file of NFS command
- service - '2049'

## SOCKS meta keys
This section includes the meta keys that specifically apply to SOCKS traffic.
- action - SOCKS request: 'connect', 'bind', 'udp associate'
- alias.host - target host of SOCKS request, if name
- alias.ip - target host of SOCKS request, if IPv4
- alias.ipv6 - target host of SOCKS request, if IPv6
- password - password credential provided to SOCKS server
- service - '1080'
- username - user credential provided to SOCKS server

## TDS meta keys
This section includes the meta keys that specifically apply to TDS traffic.
- action - SQL command: 'bulk write', 'login', 'rpc request', or batch command performed
- service - '1433'
- sql - SQL query performed

## GNUTELLA meta keys
This section includes the meta keys that specifically apply to GNUTELLA traffic.
- action - gnutella command: 'connect', 'get'
- service - '6346'

## SMTP meta keys
This section includes the meta keys that specifically apply to SMTP traffic.
- action - SMTP command
- alias.host - host from client or server greeting banner (if hostname)
- alias.ip - host from client or server greeting banner (if IPv4 address)
- alias.ipv6 - host from client or server greeting banner (if IPv6 address)
- email - address from MAIL FROM and RCPT TO request
- email.dst - address from RCPT TO, VRFY, and EXPN requests (optional)
- email.src - address from MAIL FROM request (optional)
- error - error code from SMTP responses
- service - '25'

## VNC meta keys
This section includes the meta keys that specifically apply to VNC traffic.
- action - 'login'
- error - 'login failure'
- service - '5900'

## FTP meta keys
This section includes the meta keys that specifically apply to FTP traffic.
- action - FTP command
- directory - target directory of FTP command
- extension - extension of filename
- filename - target filename of FTP command
- link - query parameters for identification of corresponding data session
- password - password credential provided to server
- service - '21'
- username - user credential provided to server

## POP3 meta keys
This section includes the meta keys that specifically apply to POP3 traffic.
- action - POP command
- ad.computer.src - host credential if NTLMSSP
- ad.domain.src - domain credential if NTLMSSP
- ad.username.src - user credential if NTLMSSP
- error - POP error
- password - password credential provided to server
- service - '110'
- username - username credential provided to serve

## MODBUS meta keys
This section includes the meta keys that specifically apply to MODBUS traffic.
- action - MODBUS protocol function
- device.type - device identification
- error - MODBUS error responses
- service - '502'

## SSH meta keys
This section includes the meta keys that specifically apply to SSH traffic.
- client - SSH client software name
- crypto - cryptography suite used for encryption of the session
- server - SSH server software name
- service - '22'
- version - client and server protocol version

## ICMP meta keys
This section includes the meta keys that specifically apply to ICMP traffic.
- action - icmp type meaning
- analysis.session - other icmp characteristics
- error - icmp code meaning
- icmp.code - raw icmp code
- icmp.type - raw icmp type
### analysis.session
This section includes specific meta values for the analysis.session meta key specific to ICMP. You must not use any values not explicitly mentioned.
- reserved icmp type

## RTSP meta keys
This section includes the meta keys that specifically apply to RTSP traffic.
- action - RTSP request method
- alias.host - uri host, if hostname
- alias.ip - uri host, if IPv4
- alias.ipv6 - uri host, if IPv6
- directory - uri path
- extension - uri filename extension
- filename - uri filename
- query - uri querystring
- service - '554'

## TFTP meta keys
This section includes the meta keys that specifically apply to TFTP traffic.
- action - 'read', 'write'
- directory - target directory of TFTP command
- extension - filename extension of target filename
- filename - target filename of TFTP command
- service - '69'

## DB2 meta keys
This section includes the meta keys that specifically apply to DB2 traffic.
- query - db2 database query
- service - '3700'

## IRC meta keys
This section includes the meta keys that specifically apply to IRC traffic.
- action - IRC command
- alias.host - target host of IRC command, if name
- alias.ip - target host of IRC command, if IPv4
- alias.ipv6 - target host of IRC command, if IPv6
- group - target channel of IRC command
- message - message sent or received
- password - password credential provided to server
- service - '6667'
- subject - text of topic command
- username - username credential provided to server

## DHCP meta keys
This section includes the meta keys that specifically apply to DHCP traffic.
- alias.host - client hostname, client fqdn
- alias.ip - client ipv4, server ipv4
- alias.ipv6 - client ipv6, server ipv6
- alias.mac - client identifier, client hardware
- extension - filename extension of bootfile
- filename - bootfile
- service - '67'

## RDP meta keys
This section includes the meta keys that specifically apply to RDP traffic.
- alias.host - client name
- language - keyboard type and layout
- service - '3389'
- username - username

## RADIUS meta keys
This section includes the meta keys that specifically apply to RADIUS traffic.
- action - packet type for requests and non-rejection responses
- alias.ip - attribute type 8, 'Framed IP Address'
- error - packet type for rejection responses
- phone - attribute type 31, 'Calling Station ID'
- service - '1812' for RADIUS, '1813' for RADIUS-ACCOUNTING
- username - attribute type 1, 'User Name'

## NETBIOS meta keys
This section includes the meta keys that specifically apply to NETBIOS traffic.
- action - opcode value from NBNS
- alias.host - server host if name
- alias.ip - server host if IPv4
- alias.ipv6 - server host if IPv6
- service - '137' (NBNS), '138' (NBDS), '139' (NBSS)

## QUIC meta keys
This section includes the meta keys that specifically apply to QUIC traffic.
- alias.host - sni from hello if hostname
- alias.ip - sni from hello if IPv4
- alias.ipv6 - sni from hello if IPv6
- client - client string from hello
- service - '443'

## NTLMSSP meta keys
This section includes the meta keys that specifically apply to NTLMSSP traffic.
- ad.computer.src - host credential provided to server
- ad.domain.src - domain credential provided to server
- ad.username.src - user credential provided to server

## BITTORRENT meta keys
This section includes the meta keys that specifically apply to BITTORRENT traffic.
- filename - name of file transferred
- service - '6881'

## DNP3 meta keys
This section includes the meta keys that specifically apply to DNP3 traffic.
- action - dnp3 function
- device.host - client identifier, server identifier
- error - dnp3 errors
- service - '20000'

## TNS meta keys
This section includes the meta keys that specifically apply to TNS traffic.
- client - client program
- database - Service Name
- host.src - client host
- service - 1521
- user - client username"""

QUERY_SYNTAX_DOC = """# NetWitness Query Syntax Guide

## WHERE Clause Operators
- **Equality**: direction='outbound'
- **Logical AND**: ip.src=10.0.0.1 && service=80
- **Logical OR**: service=80 || tcp.dstport=80
- **Logical OR for same meta key**: service=80,443
- **NOT Equal**: service!=80
- **NOT**: ~(service=80 || tcp.dstport=80)
- **Ranges**: tcp.dstport=1000-2000 or threat.score=80-100
- **Contains**: filename contains 'malware'
- **Begins with**: domain begins 'goo'
- **Ends with**: domain ends 'bar'
- **Exists check**: username exists
- **Does not exist check**: username !exists
- **CIDR notation**: ip.src=10.0.0.0/8
- **Is greater than**: tcp.dsport>443
- **Is smaller than**: tcp.dsport<443
- **Is greater or equal than**: tcp.dsport>=443
- **Is smaller or equal than**: tcp.dsport<=443
- **Regular expression**: alias.host regex('.*')
- **Evaluate number of characters in value**: length(alias.host)>20

## SELECT Clause
- **Specific fields**: select ip.src,ip.dst,service
- **All fields**: select * (default if omitted)
- **Note**: Limiting fields reduces query time and data volume

## Time Ranges
- Last 30 minutes: 30m
- Last 1 hour: 1h (default)
- Last 24 hours: 24h
- Last 2 days: 48h
- Custom: Use standard time notation (m=minutes, h=hours)
- Never use d=days, use multiples of hours instead

## Query Considerations
- Never quote IP addresses
- Never quote numerical values such as service, port numbers, size, payload
- Text and string values must always be quoted

## Query Examples

### Basic Queries
- SSH traffic: service=22
- HTTPS traffic: service=443
- Specific IP: ip.src=192.168.1.100

### Combined Conditions
- Outbound to China: ip.src=10.0.0.0/8 && country.dst='china'
- High-risk web traffic: service=80 && threat.score=80-100
- User web activity: username='jdoe' && (service=80 || service=443)

### Threat Hunting
- Suspicious files: filename contains 'exe' && threat.score=50-100
- External connections: ip.dst!=10.0.0.0/8 && ip.dst!=172.16.0.0/12

### Advanced Filters
- Large transfers: size=10000000-999999999
- Multiple ports: tcp.dstport=1000-2000 || tcp.dstport=8000-9000
- Specific domains: domain contains 'suspicious.com'

## Tips
1. Start with most specific conditions first
2. Use CIDR notation for IP ranges
3. Combine related conditions with &&
4. Use exists to find sessions with specific meta keys populated
5. Range queries are efficient for numeric values"""


# ---------------------------------------------------------------------------
# Resources (raw markdown - resources are documentation, not tool output)
# ---------------------------------------------------------------------------
@mcp.resource("netwitness://meta-keys")
def get_meta_keys() -> str:
    """NetWitness available meta keys and their descriptions."""
    return META_KEYS_DOC


@mcp.resource("netwitness://query-syntax")
def get_query_syntax() -> str:
    """NetWitness query syntax guide."""
    return QUERY_SYNTAX_DOC


# ---------------------------------------------------------------------------
# Documentation tools (Gemini CLI compatibility) - JSON envelope
# ---------------------------------------------------------------------------
@mcp.tool(annotations={"readOnlyHint": True})
async def get_netwitness_meta_keys() -> str:
    """Returns the complete list of available NetWitness meta keys and their descriptions for use in query_sessions and query_metakey_values. Call this *before* constructing any query."""
    return _success(
        tool="get_netwitness_meta_keys",
        data={"format": "markdown", "content": META_KEYS_DOC},
        metadata={"length_chars": len(META_KEYS_DOC)},
    )


@mcp.tool(annotations={"readOnlyHint": True})
async def get_netwitness_query_syntax() -> str:
    """Returns the NetWitness query syntax guide (operators, WHERE/SELECT clauses, time ranges, examples). Call this *before* constructing any query."""
    return _success(
        tool="get_netwitness_query_syntax",
        data={"format": "markdown", "content": QUERY_SYNTAX_DOC},
        metadata={"length_chars": len(QUERY_SYNTAX_DOC)},
    )


# ---------------------------------------------------------------------------
# query_sessions
# ---------------------------------------------------------------------------
@mcp.tool(annotations={"readOnlyHint": True, "sensitiveHint": "High"})
async def query_sessions(
    where_clause: str = "",
    select_clause: str = "",
    time_range: str = "1h",
    max_results: int = 1000,
) -> str:
    """Queries NetWitness sessions using SQL-like WHERE clause syntax. IMPORTANT: Check resources netwitness://meta-keys for available fields and netwitness://query-syntax for syntax examples before building queries. Time range examples: 30m, 1h, 24h. Returns structured session records grouped by sessionid."""
    tool = "query_sessions"
    query_echo = {
        "where_clause": where_clause,
        "select_clause": select_clause or "*",
        "time_range": time_range,
        "max_results": max_results,
    }
    logger.info("Executing %s: %s", tool, query_echo)

    # ---- validation ----
    if not API_URL.strip():
        return _error(tool, "config_error", "NETWITNESS_API_URL is not configured.", query_echo)
    if not API_USERNAME.strip() or not API_PASSWORD.strip():
        return _error(tool, "config_error", "NETWITNESS_USERNAME or NETWITNESS_PASSWORD are not configured.", query_echo)
    try:
        parse_time_range(time_range)
    except ValueError as e:
        return _error(tool, "validation_error", str(e), query_echo)
    if max_results <= 0:
        return _error(tool, "validation_error", "max_results must be positive.", query_echo)

    # ---- build query ----
    select_clause_eff = select_clause.strip() or "*"
    select_part = f"select {select_clause_eff}"
    time_part = f"time=rtp(now,{time_range})-u"
    if where_clause.strip():
        where_part = f"where {where_clause.strip()} && {time_part}"
    else:
        where_part = f"where {time_part}"
    query_str = f"{select_part} {where_part}"

    encoded_query = quote_plus(query_str)
    url = (
        f"{API_URL}/sdk?msg=query"
        f"&force-content-type=application/json"
        f"&size={max_results}"
        f"&query={encoded_query}"
    )

    # ---- execute ----
    try:
        async with httpx.AsyncClient(auth=(API_USERNAME, API_PASSWORD), verify=False) as client:
            response = await client.get(url, timeout=DEFAULT_HTTP_TIMEOUT)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as e:
        return _error(
            tool, "http_error",
            f"NetWitness API returned HTTP {e.response.status_code}: {e.response.text[:500]}",
            query_echo,
            metadata={"http_status": e.response.status_code},
        )
    except httpx.RequestError as e:
        return _error(tool, "request_error", f"Unable to connect to NetWitness API: {e}", query_echo)
    except Exception as e:
        logger.exception("Unexpected error in %s", tool)
        return _error(tool, "unexpected_error", str(e), query_echo)

    # ---- parse: group fields by sessionid ----
    fields = data.get("results", {}).get("fields", []) or []
    sessions: dict[Any, dict[str, Any]] = {}
    session_order: list[Any] = []

    for item in fields:
        group_id = item.get("group")
        if group_id is None:
            continue
        if group_id not in sessions:
            sessions[group_id] = {"session_id": group_id, "fields": {}}
            session_order.append(group_id)
        field_type = item.get("type", "unknown")
        field_value = item.get("value")
        bucket = sessions[group_id]["fields"]
        # Multiple values for the same meta key -> coerce to a list
        if field_type in bucket:
            existing = bucket[field_type]
            if isinstance(existing, list):
                existing.append(field_value)
            else:
                bucket[field_type] = [existing, field_value]
        else:
            bucket[field_type] = field_value

    sessions_list = [sessions[g] for g in session_order]

    if not sessions_list:
        return _success(
            tool=tool,
            data={"sessions": []},
            query=query_echo,
            metadata={"session_count": 0, "field_count": 0, "constructed_query": query_str},
        )

    return _success(
        tool=tool,
        data={"sessions": sessions_list},
        query=query_echo,
        metadata={
            "session_count": len(sessions_list),
            "field_count": len(fields),
            "constructed_query": query_str,
        },
    )


# ---------------------------------------------------------------------------
# query_metakey_values
# ---------------------------------------------------------------------------
@mcp.tool(annotations={"readOnlyHint": True, "sensitiveHint": "High"})
async def query_metakey_values(
    meta_key: str,
    where_clause: str = "",
    time_range: str = "1h",
    limit: int = 100,
    sort_order: str = "descending",
) -> str:
    """Gets aggregated values for a specific NetWitness meta key with counts (top-N query). Use where_clause to filter results (e.g., 'service=443'). Check resources netwitness://meta-keys and netwitness://query-syntax before building queries. sort_order: 'descending' (default) or 'ascending'."""
    tool = "query_metakey_values"
    query_echo = {
        "meta_key": meta_key,
        "where_clause": where_clause,
        "time_range": time_range,
        "limit": limit,
        "sort_order": sort_order,
    }
    logger.info("Executing %s: %s", tool, query_echo)

    # ---- validation ----
    if not API_URL.strip():
        return _error(tool, "config_error", "NETWITNESS_API_URL is not configured.", query_echo)
    if not API_USERNAME.strip() or not API_PASSWORD.strip():
        return _error(tool, "config_error", "NETWITNESS_USERNAME or NETWITNESS_PASSWORD are not configured.", query_echo)
    if not meta_key or not meta_key.strip():
        return _error(tool, "validation_error", "meta_key is required.", query_echo)
    if sort_order.lower() not in ("descending", "ascending"):
        return _error(tool, "validation_error", f"sort_order must be 'descending' or 'ascending'; got {sort_order!r}", query_echo)
    try:
        parse_time_range(time_range)
    except ValueError as e:
        return _error(tool, "validation_error", str(e), query_echo)
    if limit <= 0:
        return _error(tool, "validation_error", "limit must be positive.", query_echo)

    order_flag = f"order-{sort_order.lower()}"
    time_filter = f"time=rtp(now,{time_range})-u"
    full_filter = f"{where_clause.strip()} && {time_filter}" if where_clause.strip() else time_filter

    params = {
        "msg": "values",
        "force-content-type": "application/json",
        "size": str(limit),
        "fieldName": meta_key,
        "flags": f"sessions,sort-total,{order_flag}",
        "where": full_filter,
    }
    param_str = "&".join(f"{k}={quote_plus(v)}" for k, v in params.items())
    url = f"{API_URL}/sdk?{param_str}"

    try:
        async with httpx.AsyncClient(auth=(API_USERNAME, API_PASSWORD), verify=False) as client:
            response = await client.get(url, timeout=DEFAULT_HTTP_TIMEOUT)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as e:
        return _error(
            tool, "http_error",
            f"NetWitness API returned HTTP {e.response.status_code}: {e.response.text[:500]}",
            query_echo,
            metadata={"http_status": e.response.status_code},
        )
    except httpx.RequestError as e:
        return _error(tool, "request_error", f"Unable to connect to NetWitness API: {e}", query_echo)
    except Exception as e:
        logger.exception("Unexpected error in %s", tool)
        return _error(tool, "unexpected_error", str(e), query_echo)

    fields = data.get("results", {}).get("fields", []) or []
    values = [
        {"value": item.get("value"), "count": item.get("count", 0)}
        for item in fields
    ]
    total_events = sum(v["count"] or 0 for v in values)

    return _success(
        tool=tool,
        data={"meta_key": meta_key, "values": values},
        query=query_echo,
        metadata={
            "unique_values": len(values),
            "total_events": total_events,
            "applied_filter": full_filter,
        },
    )


# ---------------------------------------------------------------------------
# JWT token retrieval (with simple in-process cache)
# ---------------------------------------------------------------------------
_token_cache: dict[str, Any] = {"token": None, "expires_at": 0.0}


async def get_netwitness_token(force_refresh: bool = False) -> Optional[str]:
    """Authenticate with the Admin Server and retrieve a JWT, cached for TOKEN_TTL_SECONDS."""
    import time
    now = time.time()
    if not force_refresh and _token_cache["token"] and _token_cache["expires_at"] > now:
        return _token_cache["token"]

    if not (NW_ADMIN_URL.strip() and NW_ADMIN_USERNAME.strip() and NW_ADMIN_PASSWORD.strip()):
        logger.error("Authentication details missing for token retrieval.")
        return None

    auth_url = f"{NW_ADMIN_URL}/rest/api/auth/userpass"
    payload = {"username": NW_ADMIN_USERNAME, "password": NW_ADMIN_PASSWORD}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(auth_url, data=payload, headers=headers, timeout=10)
            response.raise_for_status()
            try:
                data = response.json()
            except Exception as json_e:
                logger.error("Failed to decode JSON from token endpoint: %s; body=%s",
                             json_e, response.text[:200])
                return None
            token = data.get("accessToken")
            if not token:
                logger.error("Token response missing 'accessToken' field.")
                return None
            _token_cache["token"] = token
            _token_cache["expires_at"] = now + TOKEN_TTL_SECONDS
            logger.info("Successfully retrieved JWT token (cached for %ds).", TOKEN_TTL_SECONDS)
            return token
    except httpx.HTTPStatusError as e:
        logger.error("Failed to get JWT token: HTTP %s - %s", e.response.status_code, e.response.text)
        return None
    except httpx.RequestError as e:
        logger.error("Request error during token retrieval: %s", e)
        return None
    except Exception as e:
        logger.exception("Unexpected error during token retrieval: %s", e)
        return None


# ---------------------------------------------------------------------------
# query_alerts
# ---------------------------------------------------------------------------
@mcp.tool(annotations={"readOnlyHint": True, "sensitiveHint": "High"})
async def query_alerts(time_range: str = "1h", max_results: int = 100) -> str:
    """Retrieves NetWitness alerts in a specified time range (e.g., 30m, 1h, 24h). Uses JWT authentication for the Alert API. Returns structured alert records including title, severity, timestamp, source/destination context, and event count."""
    tool = "query_alerts"
    query_echo = {"time_range": time_range, "max_results": max_results}
    logger.info("Executing %s: %s", tool, query_echo)

    # ---- validation ----
    if not NW_ADMIN_URL.strip():
        return _error(tool, "config_error", "NW_ADMIN_URL is not configured.", query_echo)
    try:
        parse_time_range(time_range)
    except ValueError as e:
        return _error(tool, "validation_error", str(e), query_echo)
    if max_results <= 0:
        return _error(tool, "validation_error", "max_results must be positive.", query_echo)

    # ---- authenticate ----
    jwt_token = await get_netwitness_token()
    if not jwt_token:
        return _error(
            tool, "auth_error",
            "Failed to retrieve a JWT token. Check NW_ADMIN_USERNAME/PASSWORD or NW_ADMIN_URL.",
            query_echo,
        )

    headers = {
        "NetWitness-Token": jwt_token,
        "Accept": "application/json;charset=UTF-8",
    }

    try:
        start_time, end_time = calculate_start_time(time_range)
    except ValueError as e:
        return _error(tool, "validation_error", f"Invalid time_range: {e}", query_echo)


    url = (
        f"{NW_ADMIN_URL}/rest/api/alerts"
        f"?since={quote_plus(start_time)}"
        f"&pageSize={max_results}"
    )

    try:
        async with httpx.AsyncClient(headers=headers, verify=False) as client:
            response = await client.get(url, timeout=DEFAULT_HTTP_TIMEOUT)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as e:
        return _error(
            tool, "http_error",
            f"NetWitness Alert API returned HTTP {e.response.status_code}: {e.response.text[:500]}",
            query_echo,
            metadata={"http_status": e.response.status_code},
        )
    except httpx.RequestError as e:
        return _error(tool, "request_error", f"Unable to connect to NetWitness Alert API: {e}", query_echo)
    except Exception as e:
        logger.exception("Unexpected error in %s", tool)
        return _error(tool, "unexpected_error", str(e), query_echo)

    raw_alerts = data.get("items", []) or []
    alerts: list[dict[str, Any]] = []
    for alert in raw_alerts:
        groupby = alert.get("alert", {}) or {}
        ts_raw = alert.get("timestamp")
        ts_iso: Optional[str] = None
        if isinstance(ts_raw, (int, float)):
            try:
                ts_iso = datetime.fromtimestamp(ts_raw / 1000, tz=timezone.utc)                     .isoformat().replace("+00:00", "Z")
            except Exception:
                ts_iso = None

        alerts.append({
            "id":                    alert.get("id"),
            "name":                  alert.get("name"),
            "priority":              alert.get("priority"),
            "timestamp_epoch_ms":    ts_raw,
            "timestamp_iso":         ts_iso,
            "num_events":            groupby.get("numEvents"),
            "source_ip":             groupby.get("groupby_source_ip"),
            "destination_ip":        groupby.get("groupby_destination_ip"),
            "destination_port":      groupby.get("groupby_destination_port"),
            "domain":                groupby.get("groupby_domain"),
            "destination_domain":    groupby.get("groupby_domain_dst"),
            "source_domain":         groupby.get("groupby_domain_src"),
            "destination_country":   groupby.get("groupby_destination_country"),
            "source_country":        groupby.get("groupby_source_country"),
            "filename":              groupby.get("groupby_filename"),
            "file_sha256":           groupby.get("groupby_file_sha_256"),
            "hostname":              groupby.get("groupby_host_name"),
            "destination_ad_user":   groupby.get("groupby_dst_usr_ad_username"),
            "destination_ad_domain": groupby.get("groupby_dst_usr_ad_domain"),
            "source_ad_user":        groupby.get("groupby_src_usr_ad_username"),
            "source_ad_domain":      groupby.get("groupby_src_usr_ad_domain"),
            "username":              groupby.get("groupby_username"),
            "destination_user":      groupby.get("groupby_user_dst"),
            "source_user":           groupby.get("groupby_user_src"),
        })

    return _success(
        tool=tool,
        data={"alerts": alerts},
        query=query_echo,
        metadata={
            "alert_count": len(alerts),
            "since": start_time,
        },
    )


# ---------------------------------------------------------------------------
# query_incidents
# ---------------------------------------------------------------------------
INCIDENTS_MAX_PAGE_SIZE = 100


@mcp.tool(annotations={"readOnlyHint": True, "sensitiveHint": "High"})
async def query_incidents(time_range: str = "1h", max_results: int = 100) -> str:
    """Retrieves NetWitness Respond incidents in a specified time range (e.g., 30m, 1h, 24h). Uses JWT authentication for the Respond API. max_results is capped at 100 (the API page-size maximum). Returns structured incident records including id, title, priority, risk score, status, alert/event counts, assignee, sources, categories, and source/destination IPs from alertMeta."""
    tool = "query_incidents"
    query_echo = {"time_range": time_range, "max_results": max_results}
    logger.info("Executing %s: %s", tool, query_echo)

    # ---- validation ----
    if not NW_ADMIN_URL.strip():
        return _error(tool, "config_error", "NW_ADMIN_URL is not configured.", query_echo)
    try:
        parse_time_range(time_range)
    except ValueError as e:
        return _error(tool, "validation_error", str(e), query_echo)
    if max_results <= 0:
        return _error(tool, "validation_error", "max_results must be positive.", query_echo)

    # Cap at the API maximum (page size limit)
    effective_max = min(max_results, INCIDENTS_MAX_PAGE_SIZE)
    capped = effective_max != max_results

    # ---- authenticate ----
    jwt_token = await get_netwitness_token()
    if not jwt_token:
        return _error(
            tool, "auth_error",
            "Failed to retrieve a JWT token. Check NW_ADMIN_USERNAME/PASSWORD or NW_ADMIN_URL.",
            query_echo,
        )

    headers = {
        "NetWitness-Token": jwt_token,
        "Accept": "application/json;charset=UTF-8",
    }

    try:
        start_time, end_time = calculate_start_time(time_range)
    except ValueError as e:
        return _error(tool, "validation_error", f"Invalid time_range: {e}", query_echo)

    url = (
        f"{NW_ADMIN_URL}/rest/api/incidents"
        f"?since={quote_plus(start_time)}"
        f"&until={quote_plus(end_time)}"
        f"&pageSize={effective_max}"
    )

    try:
        async with httpx.AsyncClient(headers=headers, verify=False) as client:
            response = await client.get(url, timeout=DEFAULT_HTTP_TIMEOUT)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as e:
        return _error(
            tool, "http_error",
            f"NetWitness Respond API returned HTTP {e.response.status_code}: {e.response.text[:500]}",
            query_echo,
            metadata={"http_status": e.response.status_code},
        )
    except httpx.RequestError as e:
        return _error(tool, "request_error", f"Unable to connect to NetWitness Respond API: {e}", query_echo)
    except Exception as e:
        logger.exception("Unexpected error in %s", tool)
        return _error(tool, "unexpected_error", str(e), query_echo)

    raw_incidents = data.get("items", []) or []

    metadata = {
        "incident_count": len(raw_incidents),
        "since": start_time,
        "until": end_time,
        "page_size": effective_max,
    }
    if capped:
        metadata["max_results_capped"] = True
        metadata["max_results_requested"] = max_results
        metadata["max_results_applied"] = effective_max

    return _success(
        tool=tool,
        data={"incidents": raw_incidents},
        query=query_echo,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# query_incident_alerts
# ---------------------------------------------------------------------------
import re

INCIDENT_ID_RE = re.compile(r"^INC-\d+$", re.IGNORECASE)
INCIDENT_ALERTS_MAX_PAGE_SIZE = 100


@mcp.tool(annotations={"readOnlyHint": True, "sensitiveHint": "High"})
async def query_incident_alerts(
    incident_id: str,
    max_results: int = 100,
    page_number: int = 0,
) -> str:
    """Retrieves all alerts associated with a specific NetWitness Respond incident. incident_id must be in the form 'INC-<number>' (e.g. 'INC-534'). max_results is capped at 100 (the API page-size maximum); use page_number to paginate through larger result sets starting from 0. Returns structured alert records with name, severity, timestamp, source/destination context, event count, and the raw alert payload."""
    tool = "query_incident_alerts"
    query_echo = {
        "incident_id": incident_id,
        "max_results": max_results,
        "page_number": page_number,
    }
    logger.info("Executing %s: %s", tool, query_echo)

    # ---- validation ----
    if not NW_ADMIN_URL.strip():
        return _error(tool, "config_error", "NW_ADMIN_URL is not configured.", query_echo)
    if not incident_id or not incident_id.strip():
        return _error(tool, "validation_error", "incident_id is required.", query_echo)
    inc_id = incident_id.strip().upper()
    if not INCIDENT_ID_RE.match(inc_id):
        return _error(
            tool, "validation_error",
            f"incident_id must look like 'INC-<number>' (e.g. 'INC-534'); got {incident_id!r}",
            query_echo,
        )
    if max_results <= 0:
        return _error(tool, "validation_error", "max_results must be positive.", query_echo)
    if page_number < 0:
        return _error(tool, "validation_error", "page_number must be >= 0.", query_echo)

    effective_max = min(max_results, INCIDENT_ALERTS_MAX_PAGE_SIZE)
    capped = effective_max != max_results

    # ---- authenticate ----
    jwt_token = await get_netwitness_token()
    if not jwt_token:
        return _error(
            tool, "auth_error",
            "Failed to retrieve a JWT token. Check NW_ADMIN_USERNAME/PASSWORD or NW_ADMIN_URL.",
            query_echo,
        )

    headers = {
        "NetWitness-Token": jwt_token,
        "Accept": "application/json;charset=UTF-8",
    }

    # URL-encode the incident id segment defensively, even though INC-### is path-safe.
    url = (
        f"{NW_ADMIN_URL}/rest/api/incidents/{quote_plus(inc_id)}/alerts"
        f"?pageSize={effective_max}&pageNumber={page_number}"
    )

    try:
        async with httpx.AsyncClient(headers=headers, verify=False) as client:
            response = await client.get(url, timeout=DEFAULT_HTTP_TIMEOUT)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as e:
        # 404 is meaningful here -> distinct code
        if e.response.status_code == 404:
            return _error(
                tool, "not_found",
                f"Incident {inc_id} not found.",
                query_echo,
                metadata={"http_status": 404},
            )
        return _error(
            tool, "http_error",
            f"NetWitness Respond API returned HTTP {e.response.status_code}: {e.response.text[:500]}",
            query_echo,
            metadata={"http_status": e.response.status_code},
        )
    except httpx.RequestError as e:
        return _error(tool, "request_error", f"Unable to connect to NetWitness Respond API: {e}", query_echo)
    except Exception as e:
        logger.exception("Unexpected error in %s", tool)
        return _error(tool, "unexpected_error", str(e), query_echo)

    # The response may be either a paginated envelope ({items: [...], pageNumber, pageSize, totalPages, totalItems})
    # or a bare list, depending on NW version. Handle both.
    if isinstance(data, list):
        raw_alerts = data
        page_meta: dict[str, Any] = {}
    else:
        raw_alerts = data.get("items", []) or []
        page_meta = {
            k: data.get(k)
            for k in ("pageNumber", "pageSize", "totalPages", "totalItems")
            if data.get(k) is not None
        }

    metadata = {
        "incident_id": inc_id,
        "alert_count": len(raw_alerts),
        "page_number": page_number,
        "page_size": effective_max,
    }
    if page_meta:
        metadata["pagination"] = page_meta
    if capped:
        metadata["max_results_capped"] = True
        metadata["max_results_requested"] = max_results
        metadata["max_results_applied"] = effective_max

    return _success(
        tool=tool,
        data={"incident_id": inc_id, "alerts": raw_alerts},
        query=query_echo,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# update_incident_status
# ---------------------------------------------------------------------------
VALID_INCIDENT_STATUSES = {
    "New",
    "Assigned",
    "InProgress",
    "Closed",
    "ClosedFalsePositive",
}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "sensitiveHint": "High"})
async def update_incident_status(incident_id: str, status: str) -> str:
    """Update the status of a NetWitness Respond incident. incident_id must look like 'INC-<number>' (e.g. 'INC-534'). status must be one of: New, Assigned, InProgress, Closed, ClosedFalsePositive. This is a write operation that modifies incident state in NetWitness."""
    tool = "update_incident_status"
    query_echo = {"incident_id": incident_id, "status": status}
    logger.info("Executing %s: %s", tool, query_echo)

    # ---- validation ----
    if not NW_ADMIN_URL.strip():
        return _error(tool, "config_error", "NW_ADMIN_URL is not configured.", query_echo)
    if not incident_id or not incident_id.strip():
        return _error(tool, "validation_error", "incident_id is required.", query_echo)
    inc_id = incident_id.strip().upper()
    if not INCIDENT_ID_RE.match(inc_id):
        return _error(
            tool, "validation_error",
            f"incident_id must look like 'INC-<number>' (e.g. 'INC-534'); got {incident_id!r}",
            query_echo,
        )
    if not status or not status.strip():
        return _error(tool, "validation_error", "status is required.", query_echo)
    status_clean = status.strip()
    # Case-insensitive match against the canonical set, but send canonical casing.
    canonical = next(
        (s for s in VALID_INCIDENT_STATUSES if s.lower() == status_clean.lower()),
        None,
    )
    if canonical is None:
        return _error(
            tool, "validation_error",
            f"status must be one of {sorted(VALID_INCIDENT_STATUSES)}; got {status!r}",
            query_echo,
        )

    # ---- authenticate ----
    jwt_token = await get_netwitness_token()
    if not jwt_token:
        return _error(
            tool, "auth_error",
            "Failed to retrieve a JWT token. Check NW_ADMIN_USERNAME/PASSWORD or NW_ADMIN_URL.",
            query_echo,
        )

    headers = {
        "NetWitness-Token": jwt_token,
        "Accept": "application/json;charset=UTF-8",
        "Content-Type": "application/json;charset=UTF-8",
    }
    url = f"{NW_ADMIN_URL}/rest/api/incidents/{quote_plus(inc_id)}"
    body = {"status": canonical}

    try:
        async with httpx.AsyncClient(headers=headers, verify=False) as client:
            response = await client.patch(url, json=body, timeout=DEFAULT_HTTP_TIMEOUT)
            response.raise_for_status()
            try:
                data = response.json()
            except Exception:
                data = {"raw": response.text}
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return _error(
                tool, "not_found",
                f"Incident {inc_id} not found.",
                query_echo,
                metadata={"http_status": 404},
            )
        return _error(
            tool, "http_error",
            f"NetWitness Respond API returned HTTP {e.response.status_code}: {e.response.text[:500]}",
            query_echo,
            metadata={"http_status": e.response.status_code},
        )
    except httpx.RequestError as e:
        return _error(tool, "request_error", f"Unable to connect to NetWitness Respond API: {e}", query_echo)
    except Exception as e:
        logger.exception("Unexpected error in %s", tool)
        return _error(tool, "unexpected_error", str(e), query_echo)

    return _success(
        tool=tool,
        data={"incident_id": inc_id, "status": canonical, "response": data},
        query=query_echo,
        metadata={"incident_id": inc_id, "new_status": canonical, "http_status": 200},
    )


# ---------------------------------------------------------------------------
# add_incident_journal_entry
# ---------------------------------------------------------------------------

@mcp.tool(annotations={"readOnlyHint": False, "sensitiveHint": "High"})
async def add_incident_journal_entry(
    incident_id: str,
    author: str,
    notes: str,
) -> str:
    """Add a journal entry to a NetWitness Respond incident. incident_id must look like 'INC-<number>' (e.g. 'INC-534'). author is the user adding the entry. notes is the journal text. This is a write operation that appends a new journal entry to the incident."""
    tool = "add_incident_journal_entry"
    query_echo = {
        "incident_id": incident_id,
        "author": author,
        "notes": notes,
    }
    logger.info("Executing %s: %s", tool, {**query_echo, "notes": f"<{len(notes or '')} chars>"})

    # ---- validation ----
    if not NW_ADMIN_URL.strip():
        return _error(tool, "config_error", "NW_ADMIN_URL is not configured.", query_echo)
    if not incident_id or not incident_id.strip():
        return _error(tool, "validation_error", "incident_id is required.", query_echo)
    inc_id = incident_id.strip().upper()
    if not INCIDENT_ID_RE.match(inc_id):
        return _error(
            tool, "validation_error",
            f"incident_id must look like 'INC-<number>' (e.g. 'INC-534'); got {incident_id!r}",
            query_echo,
        )
    if not author or not author.strip():
        return _error(tool, "validation_error", "author is required.", query_echo)
    if not notes or not notes.strip():
        return _error(tool, "validation_error", "notes is required.", query_echo)

    # ---- authenticate ----
    jwt_token = await get_netwitness_token()
    if not jwt_token:
        return _error(
            tool, "auth_error",
            "Failed to retrieve a JWT token. Check NW_ADMIN_USERNAME/PASSWORD or NW_ADMIN_URL.",
            query_echo,
        )

    headers = {
        "NetWitness-Token": jwt_token,
        "Accept": "application/json;charset=UTF-8",
        "Content-Type": "application/json;charset=UTF-8",
    }
    url = f"{NW_ADMIN_URL}/rest/api/incidents/{quote_plus(inc_id)}/journal"
    body = {
        "author": author.strip(),
        "notes": notes,
    }

    try:
        async with httpx.AsyncClient(headers=headers, verify=False) as client:
            response = await client.post(url, json=body, timeout=DEFAULT_HTTP_TIMEOUT)
            response.raise_for_status()
            try:
                data = response.json()
            except Exception:
                data = {"raw": response.text}
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return _error(
                tool, "not_found",
                f"Incident {inc_id} not found.",
                query_echo,
                metadata={"http_status": 404},
            )
        return _error(
            tool, "http_error",
            f"NetWitness Respond API returned HTTP {e.response.status_code}: {e.response.text[:500]}",
            query_echo,
            metadata={"http_status": e.response.status_code},
        )
    except httpx.RequestError as e:
        return _error(tool, "request_error", f"Unable to connect to NetWitness Respond API: {e}", query_echo)
    except Exception as e:
        logger.exception("Unexpected error in %s", tool)
        return _error(tool, "unexpected_error", str(e), query_echo)

    return _success(
        tool=tool,
        data={
            "incident_id": inc_id,
            "journal_entry": {
                "author": author.strip(),
                "notes": notes,
            },
            "response": data,
        },
        query=query_echo,
        metadata={"incident_id": inc_id, "http_status": response.status_code},
    )


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting NetWitness MCP server...")
    if not API_URL:
        logger.warning("NETWITNESS_API_URL environment variable is not set.")
    if not API_USERNAME:
        logger.warning("NETWITNESS_USERNAME environment variable is not set.")
    if not API_PASSWORD:
        logger.warning("NETWITNESS_PASSWORD environment variable is not set.")
    if not NW_ADMIN_URL:
        logger.warning("NW_ADMIN_URL environment variable is not set.")

    logger.info("Available tools: query_sessions, query_metakey_values, query_alerts, "
                "query_incidents, query_incident_alerts, "
                "update_incident_status, add_incident_journal_entry, "
                "get_netwitness_meta_keys, get_netwitness_query_syntax")
    logger.info("Available resources: netwitness://meta-keys, netwitness://query-syntax")

    try:
        mcp.run(transport="stdio")
    except Exception as e:
        logger.exception("Server error: %s", e)
        sys.exit(1)
