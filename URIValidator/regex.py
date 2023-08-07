'''
   URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]

   hier-part     = "//" authority path-abempty
                 / path-absolute
                 / path-rootless
                 / path-empty

   URI-reference = URI / relative-ref

   absolute-URI  = scheme ":" hier-part [ "?" query ]

   relative-ref  = relative-part [ "?" query ] [ "#" fragment ]

   relative-part = "//" authority path-abempty
                 / path-absolute
                 / path-noscheme
                 / path-empty

   scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )

   authority     = [ userinfo "@" ] host [ ":" port ]
   userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
   host          = IP-literal / IPv4address / reg-name
   port          = *DIGIT

   IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"

   IPvFuture     = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )

   IPv6address   =                            6( h16 ":" ) ls32
                 /                       "::" 5( h16 ":" ) ls32
                 / [               h16 ] "::" 4( h16 ":" ) ls32
                 / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
                 / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
                 / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
                 / [ *4( h16 ":" ) h16 ] "::"              ls32
                 / [ *5( h16 ":" ) h16 ] "::"              h16
                 / [ *6( h16 ":" ) h16 ] "::"

   h16           = 1*4HEXDIG
   ls32          = ( h16 ":" h16 ) / IPv4address
   IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet



   dec-octet     = DIGIT                 ; 0-9
                 / %x31-39 DIGIT         ; 10-99
                 / "1" 2DIGIT            ; 100-199
                 / "2" %x30-34 DIGIT     ; 200-249
                 / "25" %x30-35          ; 250-255

   reg-name      = *( unreserved / pct-encoded / sub-delims )

   path          = path-abempty    ; begins with "/" or is empty
                 / path-absolute   ; begins with "/" but not "//"
                 / path-noscheme   ; begins with a non-colon segment
                 / path-rootless   ; begins with a segment
                 / path-empty      ; zero characters

   path-abempty  = *( "/" segment )
   path-absolute = "/" [ segment-nz *( "/" segment ) ]
   path-noscheme = segment-nz-nc *( "/" segment )
   path-rootless = segment-nz *( "/" segment )
   path-empty    = 0<pchar>

   segment       = *pchar
   segment-nz    = 1*pchar
   segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
                 ; non-zero-length segment without any colon ":"

   pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"

   query         = *( pchar / "/" / "?" )

   fragment      = *( pchar / "/" / "?" )

   pct-encoded   = "%" HEXDIG HEXDIG

   unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
   reserved      = gen-delims / sub-delims
   gen-delims    = ":" / "/" / "?" / "#" / "[" / "]" / "@"
   sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
                 / "*" / "+" / "," / ";" / "="

'''
SUB_DELIMS  = r"[!$&'()*+,;=]"
GEN_DELIMS  = r"[:/?#\[\]@]"

RESERVED = fr"({GEN_DELIMS}|{SUB_DELIMS})"


UNRESERVED = r"[\w\-._~]"

PCT_ENCODED = r"%[0-9a-fA-F]{2}"

PCHAR = fr"({UNRESERVED}|{PCT_ENCODED}|{SUB_DELIMS}|:|@)"

QUERY = fr"({PCHAR}|\/|\?)*"
FRAGMENT = fr"({PCHAR}|\/|\?)*"

SEGMENT = fr"{PCHAR}*"
SEGMENT_NZ = fr"{PCHAR}+"
SEGMENT_NZ_NC = fr"({UNRESERVED}|{PCT_ENCODED}|{SUB_DELIMS}|@)+"
REG_NAME = fr"({UNRESERVED}|{PCT_ENCODED}|{SUB_DELIMS})*"


PATH_ROOTLESS = fr"{SEGMENT_NZ}(\/{SEGMENT})*"
PATH_NOSCHEME = fr"{SEGMENT_NZ_NC}(\/{SEGMENT})*"
PATH_ABSOLUTE = fr"\/{SEGMENT_NZ}(\/{SEGMENT})*"
PATH_ABEMPTY = fr"(\/{SEGMENT})*"

PATH = fr"({PATH_ABEMPTY}|{PATH_ABSOLUTE}|{PATH_NOSCHEME}|{PATH_ROOTLESS})?"

HEX_DIGIT = r"[0-9a-fA-F]"
DEC_OCTET = r"(\d|([1-9]\d)|(1\d\d)|(2[0-4]\d)|(25[0-5]))"
IPv4address = fr"{DEC_OCTET}.{DEC_OCTET}.{DEC_OCTET}.{DEC_OCTET}"
H16 = fr"{HEX_DIGIT}{{1-4}}"
LS32 = fr"(({H16}:{H16})|{IPv4address})"

IPv6address = fr"(({H16}:){{6}}{LS32})|"\
              fr"(::(({H16}:){{5}}{LS32}))|"\
              fr"({H16}::(({H16}:){{4}}{LS32}))|"\
              fr"(({H16}:){{1}}{H16}::(({H16}:){{3}}{LS32}))|"\
              fr"(({H16}:){{2}}{H16}::(({H16}:){{2}}{LS32}))|"\
              fr"(({H16}:){{3}}{H16}::{H16}:{LS32})|"\
              fr"(({H16}:){{4}}{H16}::{LS32})|"\
              fr"(({H16}:){{5}}{H16}::{H16})|"\
              fr"(({H16}:){{6}}{H16}::)"


IPvFuture = fr"(v|V){HEX_DIGIT}.({UNRESERVED}|{SUB_DELIMS}|:)+"

IP_LITERAL = fr"\[({IPv6address}|{IPvFuture})\]"

PORT = r"\d*"
HOST = fr"({IP_LITERAL}|{IPv4address}|{REG_NAME})"
USERINFO = fr"({UNRESERVED}|{PCT_ENCODED}|{SUB_DELIMS}|:)*"
AUTHORITY = fr"({USERINFO}@){HOST}(:{PORT})"
SCHEME = r"[a-zA-Z][a-zA-Z0-9+\-.]*"
RELATIVE_PART = fr"(\/\/{AUTHORITY}({PATH_ABEMPTY}|{PATH_ABSOLUTE}|{PATH_NOSCHEME}))?"
# relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
RELATIVE_REF = fr"{RELATIVE_PART}(\?{QUERY})?(#{FRAGMENT})?"
# absolute-URI  = scheme ":" hier-part [ "?" query ]
ABSOLUTE_URI = fr"{SCHEME}:{H}"
