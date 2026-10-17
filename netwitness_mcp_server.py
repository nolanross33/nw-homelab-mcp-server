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
             metadata: Optional[dict] = None, status: str = "success") -> str:
    md = {"generated_at": _now_iso()}
    if metadata:
        md.update(metadata)
    return _envelope(status, tool, query=query, data=data, metadata=md)


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
# lookup_indicator
# ---------------------------------------------------------------------------
import socket
from urllib.parse import urlparse as _urlparse

# Verified against real NetWitness events (see threat-feed-fix project):
# the two abuse.ch feeds land as device.type='abuse.ch_feodo' /
# 'abuse.ch_urlhaus'. IP indicators live in ip.dst; domain indicators live
# in host.dst (NOT domain/alias.host -- alias.host on these events is just
# the sending host, "k3s-node0"). Retention is 7 days, so the feed check
# can never see further back than that.
FEED_DEVICE_TYPES = ("abuse.ch_feodo", "abuse.ch_urlhaus")
# NetWitness's rtp() rejects the 'd' time unit (verified empirically via
# probe_feed_query.py against the live lab -- rtp(now,7d)-u errors,
# rtp(now,168h)-u doesn't). 168h = 7 days, so FEED_WINDOW uses hours while
# FEED_WINDOW_HUMAN keeps the days phrasing for the summary text; the two
# are deliberately not derived from each other -- if you change one,
# update the other to match.
FEED_WINDOW = "168h"
FEED_WINDOW_HUMAN = "7 days"
parse_time_range(FEED_WINDOW)  # sanity-check: raises ValueError if malformed
FEED_MAX_MATCHES = 10

# The incident scan filters on incident *creation* time (the Respond API's
# since/until), not last-updated. Verified live: INC-197/INC-198 were created
# 2 days earlier, still "New" and still being updated, and a 24h window
# missed both. Use the same 7-day window as the feed check.
INCIDENT_WINDOW = "168h"
INCIDENT_WINDOW_HUMAN = "7 days"
parse_time_range(INCIDENT_WINDOW)  # sanity-check: raises ValueError if malformed

# UNVERIFIED: NetWitness's exact negation syntax for excluding multiple
# device.type values has not been confirmed against a live system. '!=' is
# assumed here (common NetWitness meta-query syntax) but must be verified
# before relying on this in production -- if wrong, feed events will leak
# back into session_count instead of being excluded by this clause.
EXCLUDE_FEED_EVENTS_CLAUSE = "device.type != 'abuse.ch_feodo' && device.type != 'abuse.ch_urlhaus'"

# Row size requested for the session-presence query. NetWitness truncates
# at this many raw RESULT ROWS, not at this many distinct sessions -- each
# session contributes ~2 rows here (one "sessionid" row, one "time" row),
# so e.g. size=1000 observed ~500 distinct sessions back, size=500 observed
# ~250 (verified empirically against the live lab). Cap detection below
# therefore compares the raw row count against this constant, not
# session_count against it -- session_count itself is always however many
# distinct sessions happened to be in the (possibly truncated) rows.
SESSION_QUERY_SIZE = 1000

# Allowlist regexes — only characters valid in those value types enter queries.
_IP_CHARS_RE = re.compile(r"^[0-9a-fA-F:\.]{1,45}$")
_DOMAIN_CHARS_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,252}[a-zA-Z0-9]$")
_MAX_RETURN_LEN = 300


def _sanitize_nw(value: Any) -> Any:
    """Strip control chars, truncate, and redact injection phrases from any NW-returned string."""
    if not isinstance(value, str):
        return value
    cleaned = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", value)
    cleaned = re.sub(
        r"(?i)(ignore\s+(your\s+)?instructions|system\s*:|<\s*system\s*>"
        r"|you\s+are\s+now|disregard)",
        "[REDACTED]",
        cleaned,
    )
    return cleaned[:_MAX_RETURN_LEN]


def _sanitize_obj(obj: Any) -> Any:
    """Recursively sanitize all string values in a dict or list."""
    if isinstance(obj, dict):
        return {k: _sanitize_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_obj(i) for i in obj]
    return _sanitize_nw(obj)


_ERROR_MESSAGE_PREVIEW_LEN = 200


def _request_target(exc: Exception) -> Optional[str]:
    """
    Extract scheme://host:port (no path, no query string, no credentials)
    from an httpx exception's underlying request, if one is attached.
    Returns None if there's no request to read (defensive -- httpx attaches
    .request to transport-level errors raised during an actual call, but
    that's not guaranteed for every exception shape).

    NOTE: httpx.HTTPError.request is a *property* that raises RuntimeError
    (not AttributeError) when unset -- plain getattr(exc, "request", None)
    does not protect against that, so the access itself must be guarded.
    """
    try:
        request = exc.request
    except Exception:
        return None
    url = getattr(request, "url", None)
    if url is None:
        return None
    try:
        scheme, host, port = url.scheme, url.host, url.port
    except Exception:
        return None
    if not scheme or not host:
        return None
    return f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"


def _describe_query_error(exc: Exception) -> str:
    """
    Describe a failed NetWitness query for inclusion in a reason/note string.

    - httpx.HTTPStatusError: actual status code + first 300 chars of the
      response body (sanitized), so the caller can see what NetWitness
      actually said.
    - Other httpx errors (ConnectError, ConnectTimeout, ReadTimeout, and
      similar transport-level failures): exception class name, the target
      as scheme://host:port only (no path/query/credentials), and the
      exception's own message (sanitized, truncated to 200 chars), e.g.
      "ConnectError to https://192.168.1.38:50103: Connection refused".
    - Anything else: just the exception class name, since there's nothing
      more structured to extract.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        body = exc.response.text[:_MAX_RETURN_LEN]
        text = _sanitize_nw(f"HTTP {status}: {body}")
        return text

    if isinstance(exc, httpx.HTTPError):
        cls = type(exc).__name__
        message = _sanitize_nw(str(exc))[:_ERROR_MESSAGE_PREVIEW_LEN]
        target = _request_target(exc)
        return f"{cls} to {target}: {message}" if target else f"{cls}: {message}"

    return type(exc).__name__


def _epoch_to_iso(value: Any) -> str:
    """
    Convert a NetWitness 'time' meta value (returned as epoch seconds) to
    an ISO 8601 UTC string. Falls back to the sanitized original value if
    it isn't numeric (defensive -- in case a future query returns it as a
    string already).
    """
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return _sanitize_nw(str(value))


def _validate_ip(value: str) -> tuple[bool, str]:
    """Return (True, normalised_ip) or (False, error_message). Checks IPv4 and IPv6."""
    v = value.strip()
    if not _IP_CHARS_RE.match(v):
        return False, f"IP contains disallowed characters: {v!r}"
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, v)
            return True, v
        except OSError:
            pass
    return False, f"Not a valid IPv4 or IPv6 address: {v!r}"


def _validate_domain(value: str) -> tuple[bool, str]:
    """Return (True, normalised_domain) or (False, error_message)."""
    v = value.strip().lower()
    if re.match(r"^[a-zA-Z0-9]{1,63}$", v):
        return True, v
    if _DOMAIN_CHARS_RE.match(v):
        return True, v
    return False, f"Not a valid domain/hostname: {v!r}"


def _extract_hostname(url_value: str) -> tuple[bool, str]:
    """Parse a URL and extract its hostname. Returns (True, host) or (False, msg)."""
    v = url_value.strip()
    if "://" not in v:
        v = "https://" + v
    try:
        parsed = _urlparse(v)
        host = parsed.hostname or ""
    except Exception:
        return False, f"Could not parse URL: {url_value!r}"
    if not host:
        return False, f"No hostname found in URL: {url_value!r}"
    return True, host


_FEED_NAME_BY_DEVICE_TYPE = {
    "abuse.ch_feodo": "feodo",
    "abuse.ch_urlhaus": "urlhaus",
}


def _extract_urlhaus_id(event_desc: Any) -> Optional[str]:
    """Pull the numeric ID out of a URLhaus event.desc value, e.g. 'URLhaus 3949637' -> '3949637'."""
    if not event_desc:
        return None
    m = re.search(r"(\d+)", str(event_desc))
    return m.group(1) if m else None


def _build_feed_match(record: dict) -> dict:
    """Turn one grouped-by-session record of raw feed fields into a match dict."""
    device_type = record.get("device.type")
    feed = _FEED_NAME_BY_DEVICE_TYPE.get(str(device_type), device_type)

    # urlhaus_id is only meaningful for URLhaus (event.desc is "URLhaus <id>"
    # there). Feodo's event.desc is a static "Feodo C2 Server" string with no
    # ID in it -- gate on feed type rather than relying on "no digits found".
    urlhaus_id = _extract_urlhaus_id(record.get("event.desc")) if feed == "urlhaus" else None

    # "time" comes back as epoch seconds -- same conversion as the
    # session-presence timestamps. Named feed_last_loaded, not last_seen:
    # this is when the fetch-urlhaus.py/fetch-feodo.py CronJob last sent
    # this entry into NetWitness, NOT when the threat was last active on
    # the wire -- abuse.ch's own data may be stale or the entry may have
    # been resent verbatim on a later run.
    raw_time = record.get("time")
    feed_last_loaded = _epoch_to_iso(raw_time) if raw_time is not None else None

    return {
        "feed": feed,
        "threat": record.get("threat.desc"),
        "threat_type": record.get("event.type"),
        "category": record.get("threat.category"),
        "status": record.get("result"),
        "port": record.get("ip.dstport"),
        "feed_last_loaded": feed_last_loaded,
        "urlhaus_id": urlhaus_id,
    }


def _dedupe_feed_matches(matches: list, limit: int) -> list:
    """
    Collapse duplicate feed hits to one entry per distinct
    (feed, threat, category, status, port, urlhaus_id) combination, keeping
    the most recent feed_last_loaded for each. Needed because Feodo resends
    its full list hourly, so the same C2 entry otherwise shows up as many
    separate "matches" that are really the same indicator re-announced.
    Returns at most `limit` matches, newest feed_last_loaded first.
    """
    best: dict[tuple, dict] = {}
    for m in matches:
        key = (m["feed"], m["threat"], m["category"], m["status"], m["port"], m["urlhaus_id"])
        existing = best.get(key)
        if existing is None or str(m.get("feed_last_loaded") or "") > str(existing.get("feed_last_loaded") or ""):
            best[key] = m
    ordered = sorted(best.values(), key=lambda m: str(m.get("feed_last_loaded") or ""), reverse=True)
    return ordered[:limit]


@mcp.tool(annotations={"readOnlyHint": True, "sensitiveHint": "High"})
async def lookup_indicator(value: str, value_type: str) -> str:
    """Check whether an IP, domain, or URL is known in NetWitness threat feeds (abuse.ch URLhaus/Feodo, device.type='abuse.ch_urlhaus'/'abuse.ch_feodo') and has appeared in sessions or incidents. value_type must be one of: ip, domain, url. All values are strictly validated before use in queries — raw user text is never interpolated into NetWitness query strings. The feed check looks at ip.dst (IPs) / host.dst (domains) over the last 7 days (NetWitness retention) and returns known_in_feeds ("true"/"false", or "unknown" only if the API isn't configured or the query fails — "false" means not seen in that 7-day window, not never-listed) plus up to 10 deduplicated feed_details matches (feed, threat, threat_type, category, status, port, feed_last_loaded, urlhaus_id -- urlhaus_id is null for Feodo matches; feed_last_loaded is ISO 8601 and means when the fetch CronJob last sent this entry into NetWitness, NOT when the threat was last active). The separate session-presence check (24h window, excludes the feed events themselves, uses ip.dst not ip.src) returns session_count/first_seen/last_seen as null (not 0 or an error string) whenever it wasn't actually run -- not configured, or the query failed -- with the reason in session_note; a genuine zero-hit result is session_count=0 with first_seen/last_seen still null. session_note is also set (non-fatally) when session_count hits the query's row cap, noting first_seen/last_seen only cover the returned rows. Top-level status is "partial" (not "success") whenever the feed or session check didn't actually produce a result; incident scan failures don't affect this. All NetWitness-returned strings are sanitized via _sanitize_obj. Linked incidents are also returned with title/status/priority/created (linked_incidents). Read-only: never calls update_incident_status or add_incident_journal_entry."""
    tool = "lookup_indicator"
    query_echo = {"value": value, "value_type": value_type}
    logger.info("Executing %s: %s", tool, query_echo)

    # ---- validate value_type ----
    if not value_type or value_type.strip().lower() not in ("ip", "domain", "url"):
        return _error(
            tool, "validation_error",
            f"value_type must be one of: ip, domain, url. Got {value_type!r}",
            query_echo,
        )
    vtype = value_type.strip().lower()

    if not value or not value.strip():
        return _error(tool, "validation_error", "value is required.", query_echo)

    # ---- validate and normalise the indicator ----
    safe_value: str
    query_host: str  # the normalised string we will embed in NW queries

    if vtype == "ip":
        ok, result = _validate_ip(value)
        if not ok:
            return _error(tool, "validation_error", result, query_echo)
        safe_value = result
        query_host = safe_value

    elif vtype == "domain":
        ok, result = _validate_domain(value)
        if not ok:
            return _error(tool, "validation_error", result, query_echo)
        safe_value = result
        query_host = safe_value

    else:  # url — extract and validate the hostname
        ok, host = _extract_hostname(value)
        if not ok:
            return _error(tool, "validation_error", host, query_echo)
        ip_ok, ip_result = _validate_ip(host)
        if ip_ok:
            safe_value = host
            query_host = ip_result
            vtype = "ip"
        else:
            dom_ok, dom_result = _validate_domain(host)
            if not dom_ok:
                return _error(
                    tool, "validation_error",
                    f"Hostname extracted from URL failed validation: {dom_result}",
                    query_echo,
                )
            safe_value = host
            query_host = dom_result
            vtype = "domain"

    # ---- check which back-ends are configured ----
    session_check_ok = bool(API_URL.strip() and API_USERNAME.strip() and API_PASSWORD.strip())
    incident_check_ok = bool(NW_ADMIN_URL.strip())

    # ---- feed check ----
    # Looks directly at the two abuse.ch feed device types rather than a
    # configurable meta key — see FEED_DEVICE_TYPES / FEED_WINDOW above.
    known_in_feeds: str  # "true" | "false" | "unknown"
    feed_details: dict[str, Any] = {}

    if not session_check_ok:
        known_in_feeds = "unknown"
        feed_details["reason"] = "NETWITNESS_API_URL/credentials not configured."
    else:
        feed_device_where = " || ".join(f"device.type='{dt}'" for dt in FEED_DEVICE_TYPES)
        feed_indicator_where = (
            f"ip.dst={query_host}" if vtype == "ip" else f"host.dst='{query_host}'"
        )
        feed_where = f"({feed_device_where}) && {feed_indicator_where}"
        feed_query_str = (
            "select device.type,threat.desc,threat.category,result,event.type,"
            f"event.desc,ip.dstport,time where {feed_where} && time=rtp(now,{FEED_WINDOW})-u"
        )
        try:
            async with httpx.AsyncClient(
                auth=(API_USERNAME, API_PASSWORD), verify=False
            ) as client:
                resp = await client.get(
                    f"{API_URL}/sdk?msg=query"
                    f"&force-content-type=application/json&size=1000"
                    f"&query={quote_plus(feed_query_str)}",
                    timeout=DEFAULT_HTTP_TIMEOUT,
                )
                resp.raise_for_status()
                feed_data = resp.json()

            feed_fields = feed_data.get("results", {}).get("fields", []) or []
            # Group by session (same pattern as query_sessions) so each
            # forwarded log line's fields are assembled into one record.
            feed_sessions: dict[Any, dict[str, Any]] = {}
            for item in feed_fields:
                group_id = item.get("group")
                if group_id is None:
                    continue
                feed_sessions.setdefault(group_id, {})[item.get("type")] = item.get("value")

            raw_matches = [_build_feed_match(rec) for rec in feed_sessions.values()]
            matches = _dedupe_feed_matches(raw_matches, FEED_MAX_MATCHES)
            matches = _sanitize_obj(matches)

            known_in_feeds = "true" if matches else "false"
            feed_details["matches"] = matches
        except Exception as exc:
            known_in_feeds = "unknown"
            feed_details["reason"] = (
                f"Feed query failed: "
                f"{_describe_query_error(exc)}"
            )

    # ---- session presence ----
    # session_count/first_seen/last_seen are None (not 0 / an error string)
    # whenever the check didn't actually run -- not configured, or the
    # query raised. A real "found nothing" result is session_count=0 with
    # first_seen/last_seen still None (there's nothing to date). The reason
    # for an unavailable check goes in session_note, not into these fields.
    session_count: Optional[int] = None
    session_count_capped = False
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    session_note: Optional[str] = None

    if not session_check_ok:
        session_note = "NETWITNESS_API_URL/credentials not configured."
    else:
        sess_base_where = (
            f"ip.dst={query_host}" if vtype == "ip" else f"alias.host='{query_host}'"
        )
        # Exclude the feed events themselves so they don't inflate
        # session_count — see EXCLUDE_FEED_EVENTS_CLAUSE above.
        sess_where = f"{sess_base_where} && {EXCLUDE_FEED_EVENTS_CLAUSE}"
        sess_query_str = (
            f"select sessionid,time where {sess_where} && time=rtp(now,24h)-u"
        )
        try:
            async with httpx.AsyncClient(
                auth=(API_USERNAME, API_PASSWORD), verify=False
            ) as client:
                resp = await client.get(
                    f"{API_URL}/sdk?msg=query"
                    f"&force-content-type=application/json&size={SESSION_QUERY_SIZE}"
                    f"&query={quote_plus(sess_query_str)}",
                    timeout=DEFAULT_HTTP_TIMEOUT,
                )
                resp.raise_for_status()
                sess_data = resp.json()

            fields = sess_data.get("results", {}).get("fields", []) or []
            session_ids_seen: set = set()
            raw_timestamps: list = []
            for item in fields:
                grp = item.get("group")
                if grp is not None:
                    session_ids_seen.add(grp)
                if item.get("type") == "time" and item.get("value") is not None:
                    raw_timestamps.append(item["value"])

            session_count = len(session_ids_seen)
            # Cap detection is on the raw ROW count hitting what we asked
            # for, not on session_count hitting some fixed number -- NW
            # truncates rows, and each session is ~2 rows here, so
            # session_count alone would under-detect truncation whenever
            # the requested size changes. If NetWitness exposes a count
            # aggregate for this query type (e.g. a count(sessionid)-style
            # SDK query) that would give an authoritative total without
            # this row/session approximation -- UNVERIFIED, not switching
            # to it without confirming it actually works against this API.
            session_count_capped = len(fields) >= SESSION_QUERY_SIZE
            if session_count_capped:
                session_note = (
                    "Results capped; first_seen and last_seen only cover the returned rows."
                )

            # "time" comes back as epoch seconds -- convert to ISO 8601.
            numeric_timestamps = []
            for t in raw_timestamps:
                try:
                    numeric_timestamps.append(float(t))
                except (TypeError, ValueError):
                    pass
            if numeric_timestamps:
                first_seen = _epoch_to_iso(min(numeric_timestamps))
                last_seen = _epoch_to_iso(max(numeric_timestamps))
            elif raw_timestamps:
                # Defensive fallback if "time" ever comes back non-numeric.
                ts_sorted = sorted(str(t) for t in raw_timestamps)
                first_seen = _sanitize_nw(ts_sorted[0])
                last_seen = _sanitize_nw(ts_sorted[-1])
        except Exception as exc:
            session_count = None
            session_count_capped = False
            first_seen = None
            last_seen = None
            session_note = (
                f"Session query failed: "
                f"{_describe_query_error(exc)}"
            )

    # ---- incident scan ----
    linked_incident_ids: list[str] = []
    linked_incidents: list[dict] = []
    incident_note: Optional[str] = None

    if not incident_check_ok:
        incident_note = "NW_ADMIN_URL not configured; incident scan skipped."
    else:
        jwt_token = await get_netwitness_token()
        if not jwt_token:
            incident_note = "JWT authentication failed; incident scan skipped."
        else:
            try:
                start_time, end_time = calculate_start_time(INCIDENT_WINDOW)
                headers = {
                    "NetWitness-Token": jwt_token,
                    "Accept": "application/json;charset=UTF-8",
                }
                async with httpx.AsyncClient(headers=headers, verify=False) as client:
                    resp = await client.get(
                        f"{NW_ADMIN_URL}/rest/api/incidents"
                        f"?since={quote_plus(start_time)}"
                        f"&until={quote_plus(end_time)}&pageSize=100",
                        timeout=DEFAULT_HTTP_TIMEOUT,
                    )
                    resp.raise_for_status()
                    inc_data = resp.json()

                raw_incidents = inc_data.get("items", []) or []
                for inc in raw_incidents:
                    inc_id_raw = str(inc.get("id", "")).strip().upper()
                    if not inc_id_raw:
                        continue
                    alert_meta = inc.get("alertMeta", {}) or {}
                    matched = False
                    for field_val in alert_meta.values():
                        vals = field_val if isinstance(field_val, list) else [field_val]
                        for v in vals:
                            # alertMeta values can be comma-joined lists
                            # ("192.168.1.10,91.219.194.58"); match whole
                            # tokens so 1.2.3.4 never matches 11.2.3.45.
                            tokens = [t.strip().lower() for t in re.split(r"[,\s;]+", str(v or "")) if t.strip()]
                            if query_host.lower() in tokens:
                                matched = True
                                break
                        if matched:
                            break
                    if matched and inc_id_raw not in linked_incident_ids:
                        linked_incident_ids.append(inc_id_raw)
                        # Context so "linked" means something: title/status/
                        # priority come from NetWitness, so sanitize + cap them.
                        linked_incidents.append({
                            "id": inc_id_raw,
                            "title": _sanitize_nw(str(inc.get("title") or ""))[:120] or None,
                            "status": _sanitize_nw(str(inc.get("status") or "")) or None,
                            "priority": _sanitize_nw(str(inc.get("priority") or "")) or None,
                            "created": _sanitize_nw(str(inc.get("created") or "")) or None,
                        })
            except Exception as exc:
                incident_note = (
                    f"Incident scan failed: "
                    f"{_describe_query_error(exc)}"
                )

    # ---- plain-English summary ----
    feed_phrase = {
        "true": f"is present in threat feeds (last {FEED_WINDOW_HUMAN})",
        "false": (
            f"was not found in threat feeds in the last {FEED_WINDOW_HUMAN} "
            "(not among entries seen in that window — not proof it was never listed)"
        ),
        "unknown": "feed status is unknown (API not configured or feed query failed)",
    }[known_in_feeds]

    if session_count is None:
        sess_phrase = "session visibility unavailable"
    elif session_count > 0:
        count_label = f"{session_count}+" if session_count_capped else str(session_count)
        sess_phrase = f"appeared in {count_label} session(s) in the last 24 h"
    else:
        sess_phrase = "was not seen in any sessions in the last 24 h"

    if linked_incident_ids:
        def _inc_label(i: dict) -> str:
            bits = [b for b in (i.get("status"), i.get("priority")) if b]
            detail = f"{i['title']}; " if i.get("title") else ""
            return f"{i['id']} ({detail}{', '.join(bits)})" if (detail or bits) else i["id"]
        inc_phrase = f"linked to incident(s): {', '.join(_inc_label(i) for i in linked_incidents[:10])}"
    elif incident_note:
        inc_phrase = f"incident scan unavailable"
    else:
        inc_phrase = f"not linked to any incident created in the last {INCIDENT_WINDOW_HUMAN}"

    summary = f"{query_host} {feed_phrase}; {sess_phrase}; {inc_phrase}."

    # "partial" (not "success") whenever the feed or session check didn't
    # actually produce a result -- known_in_feeds "unknown" or
    # session_count null. Incident scan failures don't affect this; they're
    # reported via incident_note/metadata only.
    response_status = "partial" if (known_in_feeds == "unknown" or session_count is None) else "success"

    return _success(
        tool=tool,
        status=response_status,
        data={
            "indicator": safe_value,
            "indicator_type": value_type.strip().lower(),
            "normalized_value": query_host,
            "known_in_feeds": known_in_feeds,
            "feed_details": feed_details,
            "session_count": session_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "session_note": session_note,
            "linked_incident_ids": linked_incident_ids[:20],
            "linked_incidents": linked_incidents[:20],
            "summary": summary,
        },
        query=query_echo,
        metadata={
            "value_type": value_type.strip().lower(),
            "session_check_performed": session_check_ok,
            "incident_check_performed": incident_check_ok and not bool(incident_note),
            "feed_check_performed": session_check_ok,
            **({"incident_note": incident_note} if incident_note else {}),
        },
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
                "get_netwitness_meta_keys, get_netwitness_query_syntax, "
                "lookup_indicator")
    logger.info("Available resources: netwitness://meta-keys, netwitness://query-syntax")

    try:
        mcp.run(transport="stdio")
    except Exception as e:
        logger.exception("Server error: %s", e)
        sys.exit(1)
