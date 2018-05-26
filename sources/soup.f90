!!! Auto-Generated Fortran API for libsoup-2.4.

module soup
  use iso_c_binding, only: c_int

  implicit none

  private c_int

  integer(c_int), parameter :: SOUP_ADDRESS_FAMILY_INVALID = -1
  integer(c_int), parameter :: SOUP_ADDRESS_FAMILY_IPV4 = 2
  integer(c_int), parameter :: SOUP_ADDRESS_FAMILY_IPV6 = 10
  integer(c_int), parameter :: SOUP_CACHE_RESPONSE_FRESH = 0
  integer(c_int), parameter :: SOUP_CACHE_RESPONSE_NEEDS_VALIDATION = 1
  integer(c_int), parameter :: SOUP_CACHE_RESPONSE_STALE = 2
  integer(c_int), parameter :: SOUP_CACHE_SINGLE_USER = 0
  integer(c_int), parameter :: SOUP_CACHE_SHARED = 1
  integer(c_int), parameter :: SOUP_CACHE_CACHEABLE = 1
  integer(c_int), parameter :: SOUP_CACHE_UNCACHEABLE = 2
  integer(c_int), parameter :: SOUP_CACHE_INVALIDATES = 4
  integer(c_int), parameter :: SOUP_CACHE_VALIDATES = 8
  integer(c_int), parameter :: SOUP_CONNECTION_NEW = 0
  integer(c_int), parameter :: SOUP_CONNECTION_CONNECTING = 1
  integer(c_int), parameter :: SOUP_CONNECTION_IDLE = 2
  integer(c_int), parameter :: SOUP_CONNECTION_IN_USE = 3
  integer(c_int), parameter :: SOUP_CONNECTION_REMOTE_DISCONNECTED = 4
  integer(c_int), parameter :: SOUP_CONNECTION_DISCONNECTED = 5
  integer(c_int), parameter :: SOUP_COOKIE_JAR_ACCEPT_ALWAYS = 0
  integer(c_int), parameter :: SOUP_COOKIE_JAR_ACCEPT_NEVER = 1
  integer(c_int), parameter :: SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY = 2
  integer(c_int), parameter :: SOUP_DATE_HTTP = 1
  integer(c_int), parameter :: SOUP_DATE_COOKIE = 2
  integer(c_int), parameter :: SOUP_DATE_RFC2822 = 3
  integer(c_int), parameter :: SOUP_DATE_ISO8601_COMPACT = 4
  integer(c_int), parameter :: SOUP_DATE_ISO8601_FULL = 5
  integer(c_int), parameter :: SOUP_DATE_ISO8601 = 5
  integer(c_int), parameter :: SOUP_DATE_ISO8601_XMLRPC = 6
  integer(c_int), parameter :: SOUP_ENCODING_UNRECOGNIZED = 0
  integer(c_int), parameter :: SOUP_ENCODING_NONE = 1
  integer(c_int), parameter :: SOUP_ENCODING_CONTENT_LENGTH = 2
  integer(c_int), parameter :: SOUP_ENCODING_EOF = 3
  integer(c_int), parameter :: SOUP_ENCODING_CHUNKED = 4
  integer(c_int), parameter :: SOUP_ENCODING_BYTERANGES = 5
  integer(c_int), parameter :: SOUP_EXPECTATION_UNRECOGNIZED = 1
  integer(c_int), parameter :: SOUP_EXPECTATION_CONTINUE = 2
  integer(c_int), parameter :: SOUP_HTTP_1_0 = 0
  integer(c_int), parameter :: SOUP_HTTP_1_1 = 1
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_NONE = 0
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_CANCELLED = 1
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_CANT_RESOLVE = 2
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_CANT_RESOLVE_PROXY = 3
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_CANT_CONNECT = 4
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_CANT_CONNECT_PROXY = 5
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_SSL_FAILED = 6
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_IO_ERROR = 7
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_MALFORMED = 8
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_TRY_AGAIN = 9
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_TOO_MANY_REDIRECTS = 10
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_TLS_FAILED = 11
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_CONTINUE = 100
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_SWITCHING_PROTOCOLS = 101
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_PROCESSING = 102
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_OK = 200
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_CREATED = 201
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_ACCEPTED = 202
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_NON_AUTHORITATIVE = 203
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_NO_CONTENT = 204
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_RESET_CONTENT = 205
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_PARTIAL_CONTENT = 206
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_MULTI_STATUS = 207
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_MULTIPLE_CHOICES = 300
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_MOVED_PERMANENTLY = 301
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_FOUND = 302
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_MOVED_TEMPORARILY = 302
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_SEE_OTHER = 303
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_NOT_MODIFIED = 304
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_USE_PROXY = 305
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_NOT_APPEARING_IN_THIS_PROTOCOL = 306
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_TEMPORARY_REDIRECT = 307
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_BAD_REQUEST = 400
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_UNAUTHORIZED = 401
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_PAYMENT_REQUIRED = 402
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_FORBIDDEN = 403
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_NOT_FOUND = 404
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_METHOD_NOT_ALLOWED = 405
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_NOT_ACCEPTABLE = 406
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_PROXY_AUTHENTICATION_REQUIRED = 407
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_PROXY_UNAUTHORIZED = 407
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_REQUEST_TIMEOUT = 408
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_CONFLICT = 409
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_GONE = 410
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_LENGTH_REQUIRED = 411
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_PRECONDITION_FAILED = 412
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_REQUEST_ENTITY_TOO_LARGE = 413
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_REQUEST_URI_TOO_LONG = 414
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_UNSUPPORTED_MEDIA_TYPE = 415
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_REQUESTED_RANGE_NOT_SATISFIABLE = 416
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_INVALID_RANGE = 416
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_EXPECTATION_FAILED = 417
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_UNPROCESSABLE_ENTITY = 422
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_LOCKED = 423
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_FAILED_DEPENDENCY = 424
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_INTERNAL_SERVER_ERROR = 500
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_NOT_IMPLEMENTED = 501
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_BAD_GATEWAY = 502
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_SERVICE_UNAVAILABLE = 503
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_GATEWAY_TIMEOUT = 504
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_HTTP_VERSION_NOT_SUPPORTED = 505
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_INSUFFICIENT_STORAGE = 507
  integer(c_int), parameter :: SOUP_KNOWN_STATUS_CODE_NOT_EXTENDED = 510
  integer(c_int), parameter :: SOUP_LOGGER_LOG_NONE = 0
  integer(c_int), parameter :: SOUP_LOGGER_LOG_MINIMAL = 1
  integer(c_int), parameter :: SOUP_LOGGER_LOG_HEADERS = 2
  integer(c_int), parameter :: SOUP_LOGGER_LOG_BODY = 3
  integer(c_int), parameter :: SOUP_MEMORY_STATIC = 0
  integer(c_int), parameter :: SOUP_MEMORY_TAKE = 1
  integer(c_int), parameter :: SOUP_MEMORY_COPY = 2
  integer(c_int), parameter :: SOUP_MEMORY_TEMPORARY = 3
  integer(c_int), parameter :: SOUP_MESSAGE_NO_REDIRECT = 2
  integer(c_int), parameter :: SOUP_MESSAGE_CAN_REBUILD = 4
  integer(c_int), parameter :: SOUP_MESSAGE_OVERWRITE_CHUNKS = 8
  integer(c_int), parameter :: SOUP_MESSAGE_CONTENT_DECODED = 16
  integer(c_int), parameter :: SOUP_MESSAGE_CERTIFICATE_TRUSTED = 32
  integer(c_int), parameter :: SOUP_MESSAGE_NEW_CONNECTION = 64
  integer(c_int), parameter :: SOUP_MESSAGE_IDEMPOTENT = 128
  integer(c_int), parameter :: SOUP_MESSAGE_IGNORE_CONNECTION_LIMITS = 256
  integer(c_int), parameter :: SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE = 512
  integer(c_int), parameter :: SOUP_MESSAGE_HEADERS_REQUEST = 0
  integer(c_int), parameter :: SOUP_MESSAGE_HEADERS_RESPONSE = 1
  integer(c_int), parameter :: SOUP_MESSAGE_HEADERS_MULTIPART = 2
  integer(c_int), parameter :: SOUP_MESSAGE_PRIORITY_VERY_LOW = 0
  integer(c_int), parameter :: SOUP_MESSAGE_PRIORITY_LOW = 1
  integer(c_int), parameter :: SOUP_MESSAGE_PRIORITY_NORMAL = 2
  integer(c_int), parameter :: SOUP_MESSAGE_PRIORITY_HIGH = 3
  integer(c_int), parameter :: SOUP_MESSAGE_PRIORITY_VERY_HIGH = 4
  integer(c_int), parameter :: SOUP_REQUEST_ERROR_BAD_URI = 0
  integer(c_int), parameter :: SOUP_REQUEST_ERROR_UNSUPPORTED_URI_SCHEME = 1
  integer(c_int), parameter :: SOUP_REQUEST_ERROR_PARSING = 2
  integer(c_int), parameter :: SOUP_REQUEST_ERROR_ENCODING = 3
  integer(c_int), parameter :: SOUP_REQUESTER_ERROR_BAD_URI = 0
  integer(c_int), parameter :: SOUP_REQUESTER_ERROR_UNSUPPORTED_URI_SCHEME = 1
  integer(c_int), parameter :: SOUP_SERVER_LISTEN_HTTPS = 1
  integer(c_int), parameter :: SOUP_SERVER_LISTEN_IPV4_ONLY = 2
  integer(c_int), parameter :: SOUP_SERVER_LISTEN_IPV6_ONLY = 4
  integer(c_int), parameter :: SOUP_SOCKET_OK = 0
  integer(c_int), parameter :: SOUP_SOCKET_WOULD_BLOCK = 1
  integer(c_int), parameter :: SOUP_SOCKET_EOF = 2
  integer(c_int), parameter :: SOUP_SOCKET_ERROR = 3
  integer(c_int), parameter :: SOUP_STATUS_NONE = 0
  integer(c_int), parameter :: SOUP_STATUS_CANCELLED = 1
  integer(c_int), parameter :: SOUP_STATUS_CANT_RESOLVE = 2
  integer(c_int), parameter :: SOUP_STATUS_CANT_RESOLVE_PROXY = 3
  integer(c_int), parameter :: SOUP_STATUS_CANT_CONNECT = 4
  integer(c_int), parameter :: SOUP_STATUS_CANT_CONNECT_PROXY = 5
  integer(c_int), parameter :: SOUP_STATUS_SSL_FAILED = 6
  integer(c_int), parameter :: SOUP_STATUS_IO_ERROR = 7
  integer(c_int), parameter :: SOUP_STATUS_MALFORMED = 8
  integer(c_int), parameter :: SOUP_STATUS_TRY_AGAIN = 9
  integer(c_int), parameter :: SOUP_STATUS_TOO_MANY_REDIRECTS = 10
  integer(c_int), parameter :: SOUP_STATUS_TLS_FAILED = 11
  integer(c_int), parameter :: SOUP_STATUS_CONTINUE = 100
  integer(c_int), parameter :: SOUP_STATUS_SWITCHING_PROTOCOLS = 101
  integer(c_int), parameter :: SOUP_STATUS_PROCESSING = 102
  integer(c_int), parameter :: SOUP_STATUS_OK = 200
  integer(c_int), parameter :: SOUP_STATUS_CREATED = 201
  integer(c_int), parameter :: SOUP_STATUS_ACCEPTED = 202
  integer(c_int), parameter :: SOUP_STATUS_NON_AUTHORITATIVE = 203
  integer(c_int), parameter :: SOUP_STATUS_NO_CONTENT = 204
  integer(c_int), parameter :: SOUP_STATUS_RESET_CONTENT = 205
  integer(c_int), parameter :: SOUP_STATUS_PARTIAL_CONTENT = 206
  integer(c_int), parameter :: SOUP_STATUS_MULTI_STATUS = 207
  integer(c_int), parameter :: SOUP_STATUS_MULTIPLE_CHOICES = 300
  integer(c_int), parameter :: SOUP_STATUS_MOVED_PERMANENTLY = 301
  integer(c_int), parameter :: SOUP_STATUS_FOUND = 302
  integer(c_int), parameter :: SOUP_STATUS_MOVED_TEMPORARILY = 302
  integer(c_int), parameter :: SOUP_STATUS_SEE_OTHER = 303
  integer(c_int), parameter :: SOUP_STATUS_NOT_MODIFIED = 304
  integer(c_int), parameter :: SOUP_STATUS_USE_PROXY = 305
  integer(c_int), parameter :: SOUP_STATUS_NOT_APPEARING_IN_THIS_PROTOCOL = 306
  integer(c_int), parameter :: SOUP_STATUS_TEMPORARY_REDIRECT = 307
  integer(c_int), parameter :: SOUP_STATUS_BAD_REQUEST = 400
  integer(c_int), parameter :: SOUP_STATUS_UNAUTHORIZED = 401
  integer(c_int), parameter :: SOUP_STATUS_PAYMENT_REQUIRED = 402
  integer(c_int), parameter :: SOUP_STATUS_FORBIDDEN = 403
  integer(c_int), parameter :: SOUP_STATUS_NOT_FOUND = 404
  integer(c_int), parameter :: SOUP_STATUS_METHOD_NOT_ALLOWED = 405
  integer(c_int), parameter :: SOUP_STATUS_NOT_ACCEPTABLE = 406
  integer(c_int), parameter :: SOUP_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407
  integer(c_int), parameter :: SOUP_STATUS_PROXY_UNAUTHORIZED = 407
  integer(c_int), parameter :: SOUP_STATUS_REQUEST_TIMEOUT = 408
  integer(c_int), parameter :: SOUP_STATUS_CONFLICT = 409
  integer(c_int), parameter :: SOUP_STATUS_GONE = 410
  integer(c_int), parameter :: SOUP_STATUS_LENGTH_REQUIRED = 411
  integer(c_int), parameter :: SOUP_STATUS_PRECONDITION_FAILED = 412
  integer(c_int), parameter :: SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE = 413
  integer(c_int), parameter :: SOUP_STATUS_REQUEST_URI_TOO_LONG = 414
  integer(c_int), parameter :: SOUP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415
  integer(c_int), parameter :: SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE = 416
  integer(c_int), parameter :: SOUP_STATUS_INVALID_RANGE = 416
  integer(c_int), parameter :: SOUP_STATUS_EXPECTATION_FAILED = 417
  integer(c_int), parameter :: SOUP_STATUS_UNPROCESSABLE_ENTITY = 422
  integer(c_int), parameter :: SOUP_STATUS_LOCKED = 423
  integer(c_int), parameter :: SOUP_STATUS_FAILED_DEPENDENCY = 424
  integer(c_int), parameter :: SOUP_STATUS_INTERNAL_SERVER_ERROR = 500
  integer(c_int), parameter :: SOUP_STATUS_NOT_IMPLEMENTED = 501
  integer(c_int), parameter :: SOUP_STATUS_BAD_GATEWAY = 502
  integer(c_int), parameter :: SOUP_STATUS_SERVICE_UNAVAILABLE = 503
  integer(c_int), parameter :: SOUP_STATUS_GATEWAY_TIMEOUT = 504
  integer(c_int), parameter :: SOUP_STATUS_HTTP_VERSION_NOT_SUPPORTED = 505
  integer(c_int), parameter :: SOUP_STATUS_INSUFFICIENT_STORAGE = 507
  integer(c_int), parameter :: SOUP_STATUS_NOT_EXTENDED = 510
  integer(c_int), parameter :: SOUP_TLD_ERROR_INVALID_HOSTNAME = 0
  integer(c_int), parameter :: SOUP_TLD_ERROR_IS_IP_ADDRESS = 1
  integer(c_int), parameter :: SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS = 2
  integer(c_int), parameter :: SOUP_TLD_ERROR_NO_BASE_DOMAIN = 3
  integer(c_int), parameter :: SOUP_WEBSOCKET_CLOSE_NORMAL = 1000
  integer(c_int), parameter :: SOUP_WEBSOCKET_CLOSE_GOING_AWAY = 1001
  integer(c_int), parameter :: SOUP_WEBSOCKET_CLOSE_PROTOCOL_ERROR = 1002
  integer(c_int), parameter :: SOUP_WEBSOCKET_CLOSE_UNSUPPORTED_DATA = 1003
  integer(c_int), parameter :: SOUP_WEBSOCKET_CLOSE_NO_STATUS = 1005
  integer(c_int), parameter :: SOUP_WEBSOCKET_CLOSE_ABNORMAL = 1006
  integer(c_int), parameter :: SOUP_WEBSOCKET_CLOSE_BAD_DATA = 1007
  integer(c_int), parameter :: SOUP_WEBSOCKET_CLOSE_POLICY_VIOLATION = 1008
  integer(c_int), parameter :: SOUP_WEBSOCKET_CLOSE_TOO_BIG = 1009
  integer(c_int), parameter :: SOUP_WEBSOCKET_CLOSE_NO_EXTENSION = 1010
  integer(c_int), parameter :: SOUP_WEBSOCKET_CLOSE_SERVER_ERROR = 1011
  integer(c_int), parameter :: SOUP_WEBSOCKET_CLOSE_TLS_HANDSHAKE = 1015
  integer(c_int), parameter :: SOUP_WEBSOCKET_CONNECTION_UNKNOWN = 0
  integer(c_int), parameter :: SOUP_WEBSOCKET_CONNECTION_CLIENT = 1
  integer(c_int), parameter :: SOUP_WEBSOCKET_CONNECTION_SERVER = 2
  integer(c_int), parameter :: SOUP_WEBSOCKET_DATA_TEXT = 1
  integer(c_int), parameter :: SOUP_WEBSOCKET_DATA_BINARY = 2
  integer(c_int), parameter :: SOUP_WEBSOCKET_ERROR_FAILED = 0
  integer(c_int), parameter :: SOUP_WEBSOCKET_ERROR_NOT_WEBSOCKET = 1
  integer(c_int), parameter :: SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE = 2
  integer(c_int), parameter :: SOUP_WEBSOCKET_ERROR_BAD_ORIGIN = 3
  integer(c_int), parameter :: SOUP_WEBSOCKET_STATE_OPEN = 1
  integer(c_int), parameter :: SOUP_WEBSOCKET_STATE_CLOSING = 2
  integer(c_int), parameter :: SOUP_WEBSOCKET_STATE_CLOSED = 3
  integer(c_int), parameter :: SOUP_XMLRPC_ERROR_ARGUMENTS = 0
  integer(c_int), parameter :: SOUP_XMLRPC_ERROR_RETVAL = 1
  integer(c_int), parameter :: SOUP_XMLRPC_FAULT_PARSE_ERROR_NOT_WELL_FORMED = -32700
  integer(c_int), parameter :: SOUP_XMLRPC_FAULT_PARSE_ERROR_UNSUPPORTED_ENCODING = -32701
  integer(c_int), parameter :: SOUP_XMLRPC_FAULT_PARSE_ERROR_INVALID_CHARACTER_FOR_ENCODING = -32702
  integer(c_int), parameter :: SOUP_XMLRPC_FAULT_SERVER_ERROR_INVALID_XML_RPC = -32600
  integer(c_int), parameter :: SOUP_XMLRPC_FAULT_SERVER_ERROR_REQUESTED_METHOD_NOT_FOUND = -32601
  integer(c_int), parameter :: SOUP_XMLRPC_FAULT_SERVER_ERROR_INVALID_METHOD_PARAMETERS = -32602
  integer(c_int), parameter :: SOUP_XMLRPC_FAULT_SERVER_ERROR_INTERNAL_XML_RPC_ERROR = -32603
  integer(c_int), parameter :: SOUP_XMLRPC_FAULT_APPLICATION_ERROR = -32500
  integer(c_int), parameter :: SOUP_XMLRPC_FAULT_SYSTEM_ERROR = -32400
  integer(c_int), parameter :: SOUP_XMLRPC_FAULT_TRANSPORT_ERROR = -32300

  interface

    function soup_address_new( &
        name, &
        port &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: name
      integer(c_int), value :: port
      type(c_ptr) soup_address_new
    end function soup_address_new

    function soup_address_new_any( &
        family, &
        port &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      integer(c_int), value :: family
      integer(c_int), value :: port
      type(c_ptr) soup_address_new_any
    end function soup_address_new_any

    function soup_address_new_from_sockaddr( &
        sa, &
        len &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: sa
      type(c_ptr), value :: len
      type(c_ptr) soup_address_new_from_sockaddr
    end function soup_address_new_from_sockaddr

    function soup_address_equal_by_ip( &
        addr1, &
        addr2 &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: addr1
      type(c_ptr), value :: addr2
      logical(c_bool) soup_address_equal_by_ip
    end function soup_address_equal_by_ip

    function soup_address_equal_by_name( &
        addr1, &
        addr2 &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: addr1
      type(c_ptr), value :: addr2
      logical(c_bool) soup_address_equal_by_name
    end function soup_address_equal_by_name

    function soup_address_get_gsockaddr(addr) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: addr
      type(c_ptr) soup_address_get_gsockaddr
    end function soup_address_get_gsockaddr

    function soup_address_get_name(addr) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: addr
      type(c_ptr) soup_address_get_name
    end function soup_address_get_name

    function soup_address_get_physical(addr) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: addr
      type(c_ptr) soup_address_get_physical
    end function soup_address_get_physical

    function soup_address_get_port(addr) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: addr
      integer(c_int) soup_address_get_port
    end function soup_address_get_port

    function soup_address_get_sockaddr( &
        addr, &
        len &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: addr
      type(c_ptr), value :: len
      type(c_ptr) soup_address_get_sockaddr
    end function soup_address_get_sockaddr

    function soup_address_hash_by_ip(addr) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: addr
      integer(c_int) soup_address_hash_by_ip
    end function soup_address_hash_by_ip

    function soup_address_hash_by_name(addr) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: addr
      integer(c_int) soup_address_hash_by_name
    end function soup_address_hash_by_name

    function soup_address_is_resolved(addr) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: addr
      logical(c_bool) soup_address_is_resolved
    end function soup_address_is_resolved

    subroutine soup_address_resolve_async( &
        addr, &
        async_context, &
        cancellable, &
        callback, &
        user_data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: addr
      type(c_ptr), value :: async_context
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
    end subroutine soup_address_resolve_async

    function soup_address_resolve_sync( &
        addr, &
        cancellable &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: addr
      type(c_ptr), value :: cancellable
      integer(c_int) soup_address_resolve_sync
    end function soup_address_resolve_sync

    function soup_auth_new( &
        type, &
        msg, &
        auth_header &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: type
      type(c_ptr), value :: msg
      type(c_ptr), value :: auth_header
      type(c_ptr) soup_auth_new
    end function soup_auth_new

    subroutine soup_auth_authenticate( &
        auth, &
        username, &
        password &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: auth
      type(c_ptr), value :: username
      type(c_ptr), value :: password
    end subroutine soup_auth_authenticate

    function soup_auth_can_authenticate(auth) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: auth
      logical(c_bool) soup_auth_can_authenticate
    end function soup_auth_can_authenticate

    subroutine soup_auth_free_protection_space( &
        auth, &
        space &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: auth
      type(c_ptr), value :: space
    end subroutine soup_auth_free_protection_space

    function soup_auth_get_authorization( &
        auth, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: auth
      type(c_ptr), value :: msg
      type(c_ptr) soup_auth_get_authorization
    end function soup_auth_get_authorization

    function soup_auth_get_host(auth) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: auth
      type(c_ptr) soup_auth_get_host
    end function soup_auth_get_host

    function soup_auth_get_info(auth) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: auth
      type(c_ptr) soup_auth_get_info
    end function soup_auth_get_info

    function soup_auth_get_protection_space( &
        auth, &
        source_uri &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: auth
      type(c_ptr), value :: source_uri
      type(c_ptr) soup_auth_get_protection_space
    end function soup_auth_get_protection_space

    function soup_auth_get_realm(auth) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: auth
      type(c_ptr) soup_auth_get_realm
    end function soup_auth_get_realm

    function soup_auth_get_saved_password( &
        auth, &
        user &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: auth
      type(c_ptr), value :: user
      type(c_ptr) soup_auth_get_saved_password
    end function soup_auth_get_saved_password

    function soup_auth_get_saved_users(auth) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: auth
      type(c_ptr) soup_auth_get_saved_users
    end function soup_auth_get_saved_users

    function soup_auth_get_scheme_name(auth) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: auth
      type(c_ptr) soup_auth_get_scheme_name
    end function soup_auth_get_scheme_name

    subroutine soup_auth_has_saved_password( &
        auth, &
        username, &
        password &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: auth
      type(c_ptr), value :: username
      type(c_ptr), value :: password
    end subroutine soup_auth_has_saved_password

    function soup_auth_is_authenticated(auth) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: auth
      logical(c_bool) soup_auth_is_authenticated
    end function soup_auth_is_authenticated

    function soup_auth_is_for_proxy(auth) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: auth
      logical(c_bool) soup_auth_is_for_proxy
    end function soup_auth_is_for_proxy

    function soup_auth_is_ready( &
        auth, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: auth
      type(c_ptr), value :: msg
      logical(c_bool) soup_auth_is_ready
    end function soup_auth_is_ready

    subroutine soup_auth_save_password( &
        auth, &
        username, &
        password &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: auth
      type(c_ptr), value :: username
      type(c_ptr), value :: password
    end subroutine soup_auth_save_password

    function soup_auth_update( &
        auth, &
        msg, &
        auth_header &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: auth
      type(c_ptr), value :: msg
      type(c_ptr), value :: auth_header
      logical(c_bool) soup_auth_update
    end function soup_auth_update

    function soup_auth_domain_accepts( &
        domain, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: domain
      type(c_ptr), value :: msg
      type(c_ptr) soup_auth_domain_accepts
    end function soup_auth_domain_accepts

    subroutine soup_auth_domain_add_path( &
        domain, &
        path &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: domain
      type(c_ptr), value :: path
    end subroutine soup_auth_domain_add_path

    subroutine soup_auth_domain_basic_set_auth_callback( &
        domain, &
        callback, &
        user_data, &
        dnotify &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: domain
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
      type(c_ptr), value :: dnotify
    end subroutine soup_auth_domain_basic_set_auth_callback

    subroutine soup_auth_domain_challenge( &
        domain, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: domain
      type(c_ptr), value :: msg
    end subroutine soup_auth_domain_challenge

    function soup_auth_domain_check_password( &
        domain, &
        msg, &
        username, &
        password &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: domain
      type(c_ptr), value :: msg
      type(c_ptr), value :: username
      type(c_ptr), value :: password
      logical(c_bool) soup_auth_domain_check_password
    end function soup_auth_domain_check_password

    function soup_auth_domain_covers( &
        domain, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: domain
      type(c_ptr), value :: msg
      logical(c_bool) soup_auth_domain_covers
    end function soup_auth_domain_covers

    subroutine soup_auth_domain_digest_set_auth_callback( &
        domain, &
        callback, &
        user_data, &
        dnotify &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: domain
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
      type(c_ptr), value :: dnotify
    end subroutine soup_auth_domain_digest_set_auth_callback

    function soup_auth_domain_get_realm(domain) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: domain
      type(c_ptr) soup_auth_domain_get_realm
    end function soup_auth_domain_get_realm

    subroutine soup_auth_domain_remove_path( &
        domain, &
        path &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: domain
      type(c_ptr), value :: path
    end subroutine soup_auth_domain_remove_path

    subroutine soup_auth_domain_set_filter( &
        domain, &
        filter, &
        filter_data, &
        dnotify &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: domain
      type(c_ptr), value :: filter
      type(c_ptr), value :: filter_data
      type(c_ptr), value :: dnotify
    end subroutine soup_auth_domain_set_filter

    subroutine soup_auth_domain_set_generic_auth_callback( &
        domain, &
        auth_callback, &
        auth_data, &
        dnotify &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: domain
      type(c_ptr), value :: auth_callback
      type(c_ptr), value :: auth_data
      type(c_ptr), value :: dnotify
    end subroutine soup_auth_domain_set_generic_auth_callback

    function soup_auth_domain_try_generic_auth_callback( &
        domain, &
        msg, &
        username &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: domain
      type(c_ptr), value :: msg
      type(c_ptr), value :: username
      logical(c_bool) soup_auth_domain_try_generic_auth_callback
    end function soup_auth_domain_try_generic_auth_callback

    function soup_auth_domain_basic_new( &
        optname1, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: optname1
      type(c_ptr), value :: varargs
      type(c_ptr) soup_auth_domain_basic_new
    end function soup_auth_domain_basic_new

    function soup_auth_domain_digest_new( &
        optname1, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: optname1
      type(c_ptr), value :: varargs
      type(c_ptr) soup_auth_domain_digest_new
    end function soup_auth_domain_digest_new

    function soup_auth_domain_digest_encode_password( &
        username, &
        realm, &
        password &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: username
      type(c_ptr), value :: realm
      type(c_ptr), value :: password
      type(c_ptr) soup_auth_domain_digest_encode_password
    end function soup_auth_domain_digest_encode_password

    subroutine soup_auth_manager_clear_cached_credentials(manager) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: manager
    end subroutine soup_auth_manager_clear_cached_credentials

    subroutine soup_auth_manager_use_auth( &
        manager, &
        uri, &
        auth &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: manager
      type(c_ptr), value :: uri
      type(c_ptr), value :: auth
    end subroutine soup_auth_manager_use_auth

    function soup_auth_negotiate_supported() bind(c)
      use iso_c_binding, only: c_bool
      logical(c_bool) soup_auth_negotiate_supported
    end function soup_auth_negotiate_supported

    function soup_buffer_new( &
        use, &
        data, &
        length &
    ) bind(c)
      use iso_c_binding, only: c_int, c_long, c_ptr
      integer(c_int), value :: use
      type(c_ptr), value :: data
      integer(c_long), value :: length
      type(c_ptr) soup_buffer_new
    end function soup_buffer_new

    function soup_buffer_new_take( &
        data, &
        length &
    ) bind(c)
      use iso_c_binding, only: c_long, c_ptr
      type(c_ptr), value :: data
      integer(c_long), value :: length
      type(c_ptr) soup_buffer_new_take
    end function soup_buffer_new_take

    function soup_buffer_new_with_owner( &
        data, &
        length, &
        owner, &
        owner_dnotify &
    ) bind(c)
      use iso_c_binding, only: c_long, c_ptr
      type(c_ptr), value :: data
      integer(c_long), value :: length
      type(c_ptr), value :: owner
      type(c_ptr), value :: owner_dnotify
      type(c_ptr) soup_buffer_new_with_owner
    end function soup_buffer_new_with_owner

    function soup_buffer_copy(buffer) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: buffer
      type(c_ptr) soup_buffer_copy
    end function soup_buffer_copy

    subroutine soup_buffer_free(buffer) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: buffer
    end subroutine soup_buffer_free

    function soup_buffer_get_as_bytes(buffer) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: buffer
      type(c_ptr) soup_buffer_get_as_bytes
    end function soup_buffer_get_as_bytes

    subroutine soup_buffer_get_data( &
        buffer, &
        data, &
        length &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: buffer
      type(c_ptr), value :: data
      type(c_ptr), value :: length
    end subroutine soup_buffer_get_data

    function soup_buffer_get_owner(buffer) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: buffer
      type(c_ptr) soup_buffer_get_owner
    end function soup_buffer_get_owner

    function soup_buffer_new_subbuffer( &
        parent, &
        offset, &
        length &
    ) bind(c)
      use iso_c_binding, only: c_long, c_ptr
      type(c_ptr), value :: parent
      integer(c_long), value :: offset
      integer(c_long), value :: length
      type(c_ptr) soup_buffer_new_subbuffer
    end function soup_buffer_new_subbuffer

    function soup_cache_new( &
        cache_dir, &
        cache_type &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: cache_dir
      integer(c_int), value :: cache_type
      type(c_ptr) soup_cache_new
    end function soup_cache_new

    subroutine soup_cache_clear(cache) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cache
    end subroutine soup_cache_clear

    subroutine soup_cache_dump(cache) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cache
    end subroutine soup_cache_dump

    subroutine soup_cache_flush(cache) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cache
    end subroutine soup_cache_flush

    function soup_cache_get_max_size(cache) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: cache
      integer(c_int) soup_cache_get_max_size
    end function soup_cache_get_max_size

    subroutine soup_cache_load(cache) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cache
    end subroutine soup_cache_load

    subroutine soup_cache_set_max_size( &
        cache, &
        max_size &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: cache
      integer(c_int), value :: max_size
    end subroutine soup_cache_set_max_size

    function soup_client_context_get_address(client) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: client
      type(c_ptr) soup_client_context_get_address
    end function soup_client_context_get_address

    function soup_client_context_get_auth_domain(client) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: client
      type(c_ptr) soup_client_context_get_auth_domain
    end function soup_client_context_get_auth_domain

    function soup_client_context_get_auth_user(client) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: client
      type(c_ptr) soup_client_context_get_auth_user
    end function soup_client_context_get_auth_user

    function soup_client_context_get_gsocket(client) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: client
      type(c_ptr) soup_client_context_get_gsocket
    end function soup_client_context_get_gsocket

    function soup_client_context_get_host(client) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: client
      type(c_ptr) soup_client_context_get_host
    end function soup_client_context_get_host

    function soup_client_context_get_local_address(client) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: client
      type(c_ptr) soup_client_context_get_local_address
    end function soup_client_context_get_local_address

    function soup_client_context_get_remote_address(client) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: client
      type(c_ptr) soup_client_context_get_remote_address
    end function soup_client_context_get_remote_address

    function soup_client_context_get_socket(client) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: client
      type(c_ptr) soup_client_context_get_socket
    end function soup_client_context_get_socket

    function soup_client_context_steal_connection(client) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: client
      type(c_ptr) soup_client_context_steal_connection
    end function soup_client_context_steal_connection

    function soup_content_sniffer_new() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_content_sniffer_new
    end function soup_content_sniffer_new

    function soup_content_sniffer_get_buffer_size(sniffer) bind(c)
      use iso_c_binding, only: c_long, c_ptr
      type(c_ptr), value :: sniffer
      integer(c_long) soup_content_sniffer_get_buffer_size
    end function soup_content_sniffer_get_buffer_size

    function soup_content_sniffer_sniff( &
        sniffer, &
        msg, &
        buffer, &
        params &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: sniffer
      type(c_ptr), value :: msg
      type(c_ptr), value :: buffer
      type(c_ptr), value :: params
      type(c_ptr) soup_content_sniffer_sniff
    end function soup_content_sniffer_sniff

    function soup_cookie_new( &
        name, &
        value, &
        domain, &
        path, &
        max_age &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: name
      type(c_ptr), value :: value
      type(c_ptr), value :: domain
      type(c_ptr), value :: path
      type(c_ptr), value :: max_age
      type(c_ptr) soup_cookie_new
    end function soup_cookie_new

    function soup_cookie_applies_to_uri( &
        cookie, &
        uri &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr), value :: uri
      logical(c_bool) soup_cookie_applies_to_uri
    end function soup_cookie_applies_to_uri

    function soup_cookie_copy(cookie) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr) soup_cookie_copy
    end function soup_cookie_copy

    function soup_cookie_domain_matches( &
        cookie, &
        host &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr), value :: host
      logical(c_bool) soup_cookie_domain_matches
    end function soup_cookie_domain_matches

    function soup_cookie_equal( &
        cookie1, &
        cookie2 &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: cookie1
      type(c_ptr), value :: cookie2
      logical(c_bool) soup_cookie_equal
    end function soup_cookie_equal

    subroutine soup_cookie_free(cookie) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
    end subroutine soup_cookie_free

    function soup_cookie_get_domain(cookie) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr) soup_cookie_get_domain
    end function soup_cookie_get_domain

    function soup_cookie_get_expires(cookie) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr) soup_cookie_get_expires
    end function soup_cookie_get_expires

    function soup_cookie_get_http_only(cookie) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: cookie
      logical(c_bool) soup_cookie_get_http_only
    end function soup_cookie_get_http_only

    function soup_cookie_get_name(cookie) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr) soup_cookie_get_name
    end function soup_cookie_get_name

    function soup_cookie_get_path(cookie) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr) soup_cookie_get_path
    end function soup_cookie_get_path

    function soup_cookie_get_secure(cookie) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: cookie
      logical(c_bool) soup_cookie_get_secure
    end function soup_cookie_get_secure

    function soup_cookie_get_value(cookie) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr) soup_cookie_get_value
    end function soup_cookie_get_value

    subroutine soup_cookie_set_domain( &
        cookie, &
        domain &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr), value :: domain
    end subroutine soup_cookie_set_domain

    subroutine soup_cookie_set_expires( &
        cookie, &
        expires &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr), value :: expires
    end subroutine soup_cookie_set_expires

    subroutine soup_cookie_set_http_only( &
        cookie, &
        http_only &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: cookie
      logical(c_bool), value :: http_only
    end subroutine soup_cookie_set_http_only

    subroutine soup_cookie_set_max_age( &
        cookie, &
        max_age &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr), value :: max_age
    end subroutine soup_cookie_set_max_age

    subroutine soup_cookie_set_name( &
        cookie, &
        name &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr), value :: name
    end subroutine soup_cookie_set_name

    subroutine soup_cookie_set_path( &
        cookie, &
        path &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr), value :: path
    end subroutine soup_cookie_set_path

    subroutine soup_cookie_set_secure( &
        cookie, &
        secure &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: cookie
      logical(c_bool), value :: secure
    end subroutine soup_cookie_set_secure

    subroutine soup_cookie_set_value( &
        cookie, &
        value &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr), value :: value
    end subroutine soup_cookie_set_value

    function soup_cookie_to_cookie_header(cookie) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr) soup_cookie_to_cookie_header
    end function soup_cookie_to_cookie_header

    function soup_cookie_to_set_cookie_header(cookie) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookie
      type(c_ptr) soup_cookie_to_set_cookie_header
    end function soup_cookie_to_set_cookie_header

    function soup_cookie_parse( &
        header, &
        origin &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: header
      type(c_ptr), value :: origin
      type(c_ptr) soup_cookie_parse
    end function soup_cookie_parse

    function soup_cookie_jar_new() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_cookie_jar_new
    end function soup_cookie_jar_new

    subroutine soup_cookie_jar_add_cookie( &
        jar, &
        cookie &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: jar
      type(c_ptr), value :: cookie
    end subroutine soup_cookie_jar_add_cookie

    subroutine soup_cookie_jar_add_cookie_with_first_party( &
        jar, &
        first_party, &
        cookie &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: jar
      type(c_ptr), value :: first_party
      type(c_ptr), value :: cookie
    end subroutine soup_cookie_jar_add_cookie_with_first_party

    function soup_cookie_jar_all_cookies(jar) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: jar
      type(c_ptr) soup_cookie_jar_all_cookies
    end function soup_cookie_jar_all_cookies

    subroutine soup_cookie_jar_delete_cookie( &
        jar, &
        cookie &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: jar
      type(c_ptr), value :: cookie
    end subroutine soup_cookie_jar_delete_cookie

    function soup_cookie_jar_get_accept_policy(jar) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: jar
      integer(c_int) soup_cookie_jar_get_accept_policy
    end function soup_cookie_jar_get_accept_policy

    function soup_cookie_jar_get_cookie_list( &
        jar, &
        uri, &
        for_http &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: jar
      type(c_ptr), value :: uri
      logical(c_bool), value :: for_http
      type(c_ptr) soup_cookie_jar_get_cookie_list
    end function soup_cookie_jar_get_cookie_list

    function soup_cookie_jar_get_cookies( &
        jar, &
        uri, &
        for_http &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: jar
      type(c_ptr), value :: uri
      logical(c_bool), value :: for_http
      type(c_ptr) soup_cookie_jar_get_cookies
    end function soup_cookie_jar_get_cookies

    function soup_cookie_jar_is_persistent(jar) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: jar
      logical(c_bool) soup_cookie_jar_is_persistent
    end function soup_cookie_jar_is_persistent

    subroutine soup_cookie_jar_save(jar) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: jar
    end subroutine soup_cookie_jar_save

    subroutine soup_cookie_jar_set_accept_policy( &
        jar, &
        policy &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: jar
      integer(c_int), value :: policy
    end subroutine soup_cookie_jar_set_accept_policy

    subroutine soup_cookie_jar_set_cookie( &
        jar, &
        uri, &
        cookie &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: jar
      type(c_ptr), value :: uri
      type(c_ptr), value :: cookie
    end subroutine soup_cookie_jar_set_cookie

    subroutine soup_cookie_jar_set_cookie_with_first_party( &
        jar, &
        uri, &
        first_party, &
        cookie &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: jar
      type(c_ptr), value :: uri
      type(c_ptr), value :: first_party
      type(c_ptr), value :: cookie
    end subroutine soup_cookie_jar_set_cookie_with_first_party

    function soup_cookie_jar_db_new( &
        filename, &
        read_only &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: filename
      logical(c_bool), value :: read_only
      type(c_ptr) soup_cookie_jar_db_new
    end function soup_cookie_jar_db_new

    function soup_cookie_jar_text_new( &
        filename, &
        read_only &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: filename
      logical(c_bool), value :: read_only
      type(c_ptr) soup_cookie_jar_text_new
    end function soup_cookie_jar_text_new

    function soup_date_new( &
        year, &
        month, &
        day, &
        hour, &
        minute, &
        second &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: year
      type(c_ptr), value :: month
      type(c_ptr), value :: day
      type(c_ptr), value :: hour
      type(c_ptr), value :: minute
      type(c_ptr), value :: second
      type(c_ptr) soup_date_new
    end function soup_date_new

    function soup_date_new_from_now(offset_seconds) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: offset_seconds
      type(c_ptr) soup_date_new_from_now
    end function soup_date_new_from_now

    function soup_date_new_from_string(date_string) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date_string
      type(c_ptr) soup_date_new_from_string
    end function soup_date_new_from_string

    function soup_date_new_from_time_t(when) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: when
      type(c_ptr) soup_date_new_from_time_t
    end function soup_date_new_from_time_t

    function soup_date_copy(date) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date
      type(c_ptr) soup_date_copy
    end function soup_date_copy

    subroutine soup_date_free(date) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date
    end subroutine soup_date_free

    function soup_date_get_day(date) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date
      type(c_ptr) soup_date_get_day
    end function soup_date_get_day

    function soup_date_get_hour(date) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date
      type(c_ptr) soup_date_get_hour
    end function soup_date_get_hour

    function soup_date_get_minute(date) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date
      type(c_ptr) soup_date_get_minute
    end function soup_date_get_minute

    function soup_date_get_month(date) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date
      type(c_ptr) soup_date_get_month
    end function soup_date_get_month

    function soup_date_get_offset(date) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date
      type(c_ptr) soup_date_get_offset
    end function soup_date_get_offset

    function soup_date_get_second(date) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date
      type(c_ptr) soup_date_get_second
    end function soup_date_get_second

    function soup_date_get_utc(date) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date
      type(c_ptr) soup_date_get_utc
    end function soup_date_get_utc

    function soup_date_get_year(date) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date
      type(c_ptr) soup_date_get_year
    end function soup_date_get_year

    function soup_date_is_past(date) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: date
      logical(c_bool) soup_date_is_past
    end function soup_date_is_past

    function soup_date_to_string( &
        date, &
        format &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: date
      integer(c_int), value :: format
      type(c_ptr) soup_date_to_string
    end function soup_date_to_string

    function soup_date_to_time_t(date) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date
      type(c_ptr) soup_date_to_time_t
    end function soup_date_to_time_t

    subroutine soup_date_to_timeval( &
        date, &
        time &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date
      type(c_ptr), value :: time
    end subroutine soup_date_to_timeval

    function soup_logger_new( &
        level, &
        max_body_size &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      integer(c_int), value :: level
      type(c_ptr), value :: max_body_size
      type(c_ptr) soup_logger_new
    end function soup_logger_new

    subroutine soup_logger_attach( &
        logger, &
        session &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: logger
      type(c_ptr), value :: session
    end subroutine soup_logger_attach

    subroutine soup_logger_detach( &
        logger, &
        session &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: logger
      type(c_ptr), value :: session
    end subroutine soup_logger_detach

    subroutine soup_logger_set_printer( &
        logger, &
        printer, &
        printer_data, &
        destroy &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: logger
      type(c_ptr), value :: printer
      type(c_ptr), value :: printer_data
      type(c_ptr), value :: destroy
    end subroutine soup_logger_set_printer

    subroutine soup_logger_set_request_filter( &
        logger, &
        request_filter, &
        filter_data, &
        destroy &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: logger
      type(c_ptr), value :: request_filter
      type(c_ptr), value :: filter_data
      type(c_ptr), value :: destroy
    end subroutine soup_logger_set_request_filter

    subroutine soup_logger_set_response_filter( &
        logger, &
        response_filter, &
        filter_data, &
        destroy &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: logger
      type(c_ptr), value :: response_filter
      type(c_ptr), value :: filter_data
      type(c_ptr), value :: destroy
    end subroutine soup_logger_set_response_filter

    function soup_message_new( &
        method, &
        uri_string &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: method
      type(c_ptr), value :: uri_string
      type(c_ptr) soup_message_new
    end function soup_message_new

    function soup_message_new_from_uri( &
        method, &
        uri &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: method
      type(c_ptr), value :: uri
      type(c_ptr) soup_message_new_from_uri
    end function soup_message_new_from_uri

    function soup_message_add_header_handler( &
        msg, &
        signal, &
        header, &
        callback, &
        user_data &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: signal
      type(c_ptr), value :: header
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
      integer(c_int) soup_message_add_header_handler
    end function soup_message_add_header_handler

    function soup_message_add_status_code_handler( &
        msg, &
        signal, &
        status_code, &
        callback, &
        user_data &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: signal
      integer(c_int), value :: status_code
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
      integer(c_int) soup_message_add_status_code_handler
    end function soup_message_add_status_code_handler

    subroutine soup_message_content_sniffed( &
        msg, &
        content_type, &
        params &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: content_type
      type(c_ptr), value :: params
    end subroutine soup_message_content_sniffed

    subroutine soup_message_disable_feature( &
        msg, &
        feature_type &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: feature_type
    end subroutine soup_message_disable_feature

    subroutine soup_message_finished(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
    end subroutine soup_message_finished

    function soup_message_get_address(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr) soup_message_get_address
    end function soup_message_get_address

    function soup_message_get_first_party(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr) soup_message_get_first_party
    end function soup_message_get_first_party

    function soup_message_get_flags(msg) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: msg
      integer(c_int) soup_message_get_flags
    end function soup_message_get_flags

    function soup_message_get_http_version(msg) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: msg
      integer(c_int) soup_message_get_http_version
    end function soup_message_get_http_version

    function soup_message_get_https_status( &
        msg, &
        certificate, &
        errors &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: certificate
      type(c_ptr), value :: errors
      logical(c_bool) soup_message_get_https_status
    end function soup_message_get_https_status

    function soup_message_get_priority(msg) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: msg
      integer(c_int) soup_message_get_priority
    end function soup_message_get_priority

    function soup_message_get_soup_request(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr) soup_message_get_soup_request
    end function soup_message_get_soup_request

    function soup_message_get_uri(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr) soup_message_get_uri
    end function soup_message_get_uri

    subroutine soup_message_got_body(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
    end subroutine soup_message_got_body

    subroutine soup_message_got_chunk( &
        msg, &
        chunk &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: chunk
    end subroutine soup_message_got_chunk

    subroutine soup_message_got_headers(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
    end subroutine soup_message_got_headers

    subroutine soup_message_got_informational(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
    end subroutine soup_message_got_informational

    function soup_message_is_keepalive(msg) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: msg
      logical(c_bool) soup_message_is_keepalive
    end function soup_message_is_keepalive

    subroutine soup_message_restarted(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
    end subroutine soup_message_restarted

    subroutine soup_message_set_chunk_allocator( &
        msg, &
        allocator, &
        user_data, &
        destroy_notify &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: allocator
      type(c_ptr), value :: user_data
      type(c_ptr), value :: destroy_notify
    end subroutine soup_message_set_chunk_allocator

    subroutine soup_message_set_first_party( &
        msg, &
        first_party &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: first_party
    end subroutine soup_message_set_first_party

    subroutine soup_message_set_flags( &
        msg, &
        flags &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: msg
      integer(c_int), value :: flags
    end subroutine soup_message_set_flags

    subroutine soup_message_set_http_version( &
        msg, &
        version &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: msg
      integer(c_int), value :: version
    end subroutine soup_message_set_http_version

    subroutine soup_message_set_priority( &
        msg, &
        priority &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: msg
      integer(c_int), value :: priority
    end subroutine soup_message_set_priority

    subroutine soup_message_set_redirect( &
        msg, &
        status_code, &
        redirect_uri &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: msg
      integer(c_int), value :: status_code
      type(c_ptr), value :: redirect_uri
    end subroutine soup_message_set_redirect

    subroutine soup_message_set_request( &
        msg, &
        content_type, &
        req_use, &
        req_body, &
        req_length &
    ) bind(c)
      use iso_c_binding, only: c_int, c_long, c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: content_type
      integer(c_int), value :: req_use
      type(c_ptr), value :: req_body
      integer(c_long), value :: req_length
    end subroutine soup_message_set_request

    subroutine soup_message_set_response( &
        msg, &
        content_type, &
        resp_use, &
        resp_body, &
        resp_length &
    ) bind(c)
      use iso_c_binding, only: c_int, c_long, c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: content_type
      integer(c_int), value :: resp_use
      type(c_ptr), value :: resp_body
      integer(c_long), value :: resp_length
    end subroutine soup_message_set_response

    subroutine soup_message_set_status( &
        msg, &
        status_code &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: msg
      integer(c_int), value :: status_code
    end subroutine soup_message_set_status

    subroutine soup_message_set_status_full( &
        msg, &
        status_code, &
        reason_phrase &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: msg
      integer(c_int), value :: status_code
      type(c_ptr), value :: reason_phrase
    end subroutine soup_message_set_status_full

    subroutine soup_message_set_uri( &
        msg, &
        uri &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: uri
    end subroutine soup_message_set_uri

    subroutine soup_message_starting(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
    end subroutine soup_message_starting

    subroutine soup_message_wrote_body(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
    end subroutine soup_message_wrote_body

    subroutine soup_message_wrote_body_data( &
        msg, &
        chunk &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: chunk
    end subroutine soup_message_wrote_body_data

    subroutine soup_message_wrote_chunk(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
    end subroutine soup_message_wrote_chunk

    subroutine soup_message_wrote_headers(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
    end subroutine soup_message_wrote_headers

    subroutine soup_message_wrote_informational(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
    end subroutine soup_message_wrote_informational

    function soup_message_body_new() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_message_body_new
    end function soup_message_body_new

    subroutine soup_message_body_append( &
        body, &
        use, &
        data, &
        length &
    ) bind(c)
      use iso_c_binding, only: c_int, c_long, c_ptr
      type(c_ptr), value :: body
      integer(c_int), value :: use
      type(c_ptr), value :: data
      integer(c_long), value :: length
    end subroutine soup_message_body_append

    subroutine soup_message_body_append_buffer( &
        body, &
        buffer &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: body
      type(c_ptr), value :: buffer
    end subroutine soup_message_body_append_buffer

    subroutine soup_message_body_append_take( &
        body, &
        data, &
        length &
    ) bind(c)
      use iso_c_binding, only: c_long, c_ptr
      type(c_ptr), value :: body
      type(c_ptr), value :: data
      integer(c_long), value :: length
    end subroutine soup_message_body_append_take

    subroutine soup_message_body_complete(body) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: body
    end subroutine soup_message_body_complete

    function soup_message_body_flatten(body) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: body
      type(c_ptr) soup_message_body_flatten
    end function soup_message_body_flatten

    subroutine soup_message_body_free(body) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: body
    end subroutine soup_message_body_free

    function soup_message_body_get_accumulate(body) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: body
      logical(c_bool) soup_message_body_get_accumulate
    end function soup_message_body_get_accumulate

    function soup_message_body_get_chunk( &
        body, &
        offset &
    ) bind(c)
      use iso_c_binding, only: c_int64_t, c_ptr
      type(c_ptr), value :: body
      integer(c_int64_t), value :: offset
      type(c_ptr) soup_message_body_get_chunk
    end function soup_message_body_get_chunk

    subroutine soup_message_body_got_chunk( &
        body, &
        chunk &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: body
      type(c_ptr), value :: chunk
    end subroutine soup_message_body_got_chunk

    subroutine soup_message_body_set_accumulate( &
        body, &
        accumulate &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: body
      logical(c_bool), value :: accumulate
    end subroutine soup_message_body_set_accumulate

    subroutine soup_message_body_truncate(body) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: body
    end subroutine soup_message_body_truncate

    subroutine soup_message_body_wrote_chunk( &
        body, &
        chunk &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: body
      type(c_ptr), value :: chunk
    end subroutine soup_message_body_wrote_chunk

    function soup_message_headers_new(type) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      integer(c_int), value :: type
      type(c_ptr) soup_message_headers_new
    end function soup_message_headers_new

    subroutine soup_message_headers_append( &
        hdrs, &
        name, &
        value &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: name
      type(c_ptr), value :: value
    end subroutine soup_message_headers_append

    subroutine soup_message_headers_clean_connection_headers(hdrs) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
    end subroutine soup_message_headers_clean_connection_headers

    subroutine soup_message_headers_clear(hdrs) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
    end subroutine soup_message_headers_clear

    subroutine soup_message_headers_foreach( &
        hdrs, &
        func, &
        user_data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: func
      type(c_ptr), value :: user_data
    end subroutine soup_message_headers_foreach

    subroutine soup_message_headers_free(hdrs) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
    end subroutine soup_message_headers_free

    subroutine soup_message_headers_free_ranges( &
        hdrs, &
        ranges &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: ranges
    end subroutine soup_message_headers_free_ranges

    function soup_message_headers_get( &
        hdrs, &
        name &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: name
      type(c_ptr) soup_message_headers_get
    end function soup_message_headers_get

    function soup_message_headers_get_content_disposition( &
        hdrs, &
        disposition, &
        params &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: disposition
      type(c_ptr), value :: params
      logical(c_bool) soup_message_headers_get_content_disposition
    end function soup_message_headers_get_content_disposition

    function soup_message_headers_get_content_length(hdrs) bind(c)
      use iso_c_binding, only: c_int64_t, c_ptr
      type(c_ptr), value :: hdrs
      integer(c_int64_t) soup_message_headers_get_content_length
    end function soup_message_headers_get_content_length

    function soup_message_headers_get_content_range( &
        hdrs, &
        start, &
        end, &
        total_length &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: start
      type(c_ptr), value :: end
      type(c_ptr), value :: total_length
      logical(c_bool) soup_message_headers_get_content_range
    end function soup_message_headers_get_content_range

    function soup_message_headers_get_content_type( &
        hdrs, &
        params &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: params
      type(c_ptr) soup_message_headers_get_content_type
    end function soup_message_headers_get_content_type

    function soup_message_headers_get_encoding(hdrs) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: hdrs
      integer(c_int) soup_message_headers_get_encoding
    end function soup_message_headers_get_encoding

    function soup_message_headers_get_expectations(hdrs) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: hdrs
      integer(c_int) soup_message_headers_get_expectations
    end function soup_message_headers_get_expectations

    function soup_message_headers_get_headers_type(hdrs) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: hdrs
      integer(c_int) soup_message_headers_get_headers_type
    end function soup_message_headers_get_headers_type

    function soup_message_headers_get_list( &
        hdrs, &
        name &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: name
      type(c_ptr) soup_message_headers_get_list
    end function soup_message_headers_get_list

    function soup_message_headers_get_one( &
        hdrs, &
        name &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: name
      type(c_ptr) soup_message_headers_get_one
    end function soup_message_headers_get_one

    function soup_message_headers_get_ranges( &
        hdrs, &
        total_length, &
        ranges, &
        length &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_int64_t, c_ptr
      type(c_ptr), value :: hdrs
      integer(c_int64_t), value :: total_length
      type(c_ptr), value :: ranges
      type(c_ptr), value :: length
      logical(c_bool) soup_message_headers_get_ranges
    end function soup_message_headers_get_ranges

    function soup_message_headers_header_contains( &
        hdrs, &
        name, &
        token &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: name
      type(c_ptr), value :: token
      logical(c_bool) soup_message_headers_header_contains
    end function soup_message_headers_header_contains

    function soup_message_headers_header_equals( &
        hdrs, &
        name, &
        value &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: name
      type(c_ptr), value :: value
      logical(c_bool) soup_message_headers_header_equals
    end function soup_message_headers_header_equals

    subroutine soup_message_headers_remove( &
        hdrs, &
        name &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: name
    end subroutine soup_message_headers_remove

    subroutine soup_message_headers_replace( &
        hdrs, &
        name, &
        value &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: name
      type(c_ptr), value :: value
    end subroutine soup_message_headers_replace

    subroutine soup_message_headers_set_content_disposition( &
        hdrs, &
        disposition, &
        params &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: disposition
      type(c_ptr), value :: params
    end subroutine soup_message_headers_set_content_disposition

    subroutine soup_message_headers_set_content_length( &
        hdrs, &
        content_length &
    ) bind(c)
      use iso_c_binding, only: c_int64_t, c_ptr
      type(c_ptr), value :: hdrs
      integer(c_int64_t), value :: content_length
    end subroutine soup_message_headers_set_content_length

    subroutine soup_message_headers_set_content_range( &
        hdrs, &
        start, &
        end, &
        total_length &
    ) bind(c)
      use iso_c_binding, only: c_int64_t, c_ptr
      type(c_ptr), value :: hdrs
      integer(c_int64_t), value :: start
      integer(c_int64_t), value :: end
      integer(c_int64_t), value :: total_length
    end subroutine soup_message_headers_set_content_range

    subroutine soup_message_headers_set_content_type( &
        hdrs, &
        content_type, &
        params &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: content_type
      type(c_ptr), value :: params
    end subroutine soup_message_headers_set_content_type

    subroutine soup_message_headers_set_encoding( &
        hdrs, &
        encoding &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: hdrs
      integer(c_int), value :: encoding
    end subroutine soup_message_headers_set_encoding

    subroutine soup_message_headers_set_expectations( &
        hdrs, &
        expectations &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: hdrs
      integer(c_int), value :: expectations
    end subroutine soup_message_headers_set_expectations

    subroutine soup_message_headers_set_range( &
        hdrs, &
        start, &
        end &
    ) bind(c)
      use iso_c_binding, only: c_int64_t, c_ptr
      type(c_ptr), value :: hdrs
      integer(c_int64_t), value :: start
      integer(c_int64_t), value :: end
    end subroutine soup_message_headers_set_range

    subroutine soup_message_headers_set_ranges( &
        hdrs, &
        ranges, &
        length &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hdrs
      type(c_ptr), value :: ranges
      type(c_ptr), value :: length
    end subroutine soup_message_headers_set_ranges

    function soup_message_headers_iter_next( &
        iter, &
        name, &
        value &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: iter
      type(c_ptr), value :: name
      type(c_ptr), value :: value
      logical(c_bool) soup_message_headers_iter_next
    end function soup_message_headers_iter_next

    subroutine soup_message_headers_iter_init( &
        iter, &
        hdrs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: iter
      type(c_ptr), value :: hdrs
    end subroutine soup_message_headers_iter_init

    function soup_multipart_new(mime_type) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: mime_type
      type(c_ptr) soup_multipart_new
    end function soup_multipart_new

    function soup_multipart_new_from_message( &
        headers, &
        body &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: headers
      type(c_ptr), value :: body
      type(c_ptr) soup_multipart_new_from_message
    end function soup_multipart_new_from_message

    subroutine soup_multipart_append_form_file( &
        multipart, &
        control_name, &
        filename, &
        content_type, &
        body &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: multipart
      type(c_ptr), value :: control_name
      type(c_ptr), value :: filename
      type(c_ptr), value :: content_type
      type(c_ptr), value :: body
    end subroutine soup_multipart_append_form_file

    subroutine soup_multipart_append_form_string( &
        multipart, &
        control_name, &
        data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: multipart
      type(c_ptr), value :: control_name
      type(c_ptr), value :: data
    end subroutine soup_multipart_append_form_string

    subroutine soup_multipart_append_part( &
        multipart, &
        headers, &
        body &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: multipart
      type(c_ptr), value :: headers
      type(c_ptr), value :: body
    end subroutine soup_multipart_append_part

    subroutine soup_multipart_free(multipart) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: multipart
    end subroutine soup_multipart_free

    function soup_multipart_get_length(multipart) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: multipart
      type(c_ptr) soup_multipart_get_length
    end function soup_multipart_get_length

    function soup_multipart_get_part( &
        multipart, &
        part, &
        headers, &
        body &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: multipart
      type(c_ptr), value :: part
      type(c_ptr), value :: headers
      type(c_ptr), value :: body
      logical(c_bool) soup_multipart_get_part
    end function soup_multipart_get_part

    subroutine soup_multipart_to_message( &
        multipart, &
        dest_headers, &
        dest_body &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: multipart
      type(c_ptr), value :: dest_headers
      type(c_ptr), value :: dest_body
    end subroutine soup_multipart_to_message

    function soup_multipart_input_stream_new( &
        msg, &
        base_stream &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: base_stream
      type(c_ptr) soup_multipart_input_stream_new
    end function soup_multipart_input_stream_new

    function soup_multipart_input_stream_get_headers(multipart) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: multipart
      type(c_ptr) soup_multipart_input_stream_get_headers
    end function soup_multipart_input_stream_get_headers

    function soup_multipart_input_stream_next_part( &
        multipart, &
        cancellable, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: multipart
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: error
      type(c_ptr) soup_multipart_input_stream_next_part
    end function soup_multipart_input_stream_next_part

    subroutine soup_multipart_input_stream_next_part_async( &
        multipart, &
        io_priority, &
        cancellable, &
        callback, &
        data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: multipart
      type(c_ptr), value :: io_priority
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: callback
      type(c_ptr), value :: data
    end subroutine soup_multipart_input_stream_next_part_async

    function soup_multipart_input_stream_next_part_finish( &
        multipart, &
        result, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: multipart
      type(c_ptr), value :: result
      type(c_ptr), value :: error
      type(c_ptr) soup_multipart_input_stream_next_part_finish
    end function soup_multipart_input_stream_next_part_finish

    subroutine soup_password_manager_get_passwords_async( &
        password_manager, &
        msg, &
        auth, &
        retrying, &
        async_context, &
        cancellable, &
        callback, &
        user_data &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: password_manager
      type(c_ptr), value :: msg
      type(c_ptr), value :: auth
      logical(c_bool), value :: retrying
      type(c_ptr), value :: async_context
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
    end subroutine soup_password_manager_get_passwords_async

    subroutine soup_password_manager_get_passwords_sync( &
        password_manager, &
        msg, &
        auth, &
        cancellable &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: password_manager
      type(c_ptr), value :: msg
      type(c_ptr), value :: auth
      type(c_ptr), value :: cancellable
    end subroutine soup_password_manager_get_passwords_sync

    subroutine soup_proxy_uri_resolver_get_proxy_uri_async( &
        proxy_uri_resolver, &
        uri, &
        async_context, &
        cancellable, &
        callback, &
        user_data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: proxy_uri_resolver
      type(c_ptr), value :: uri
      type(c_ptr), value :: async_context
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
    end subroutine soup_proxy_uri_resolver_get_proxy_uri_async

    function soup_proxy_uri_resolver_get_proxy_uri_sync( &
        proxy_uri_resolver, &
        uri, &
        cancellable, &
        proxy_uri &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: proxy_uri_resolver
      type(c_ptr), value :: uri
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: proxy_uri
      integer(c_int) soup_proxy_uri_resolver_get_proxy_uri_sync
    end function soup_proxy_uri_resolver_get_proxy_uri_sync

    function soup_request_get_content_length(request) bind(c)
      use iso_c_binding, only: c_int64_t, c_ptr
      type(c_ptr), value :: request
      integer(c_int64_t) soup_request_get_content_length
    end function soup_request_get_content_length

    function soup_request_get_content_type(request) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: request
      type(c_ptr) soup_request_get_content_type
    end function soup_request_get_content_type

    function soup_request_get_session(request) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: request
      type(c_ptr) soup_request_get_session
    end function soup_request_get_session

    function soup_request_get_uri(request) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: request
      type(c_ptr) soup_request_get_uri
    end function soup_request_get_uri

    function soup_request_send( &
        request, &
        cancellable, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: request
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: error
      type(c_ptr) soup_request_send
    end function soup_request_send

    subroutine soup_request_send_async( &
        request, &
        cancellable, &
        callback, &
        user_data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: request
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
    end subroutine soup_request_send_async

    function soup_request_send_finish( &
        request, &
        result, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: request
      type(c_ptr), value :: result
      type(c_ptr), value :: error
      type(c_ptr) soup_request_send_finish
    end function soup_request_send_finish

    function soup_request_error_quark() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_request_error_quark
    end function soup_request_error_quark

    function soup_request_file_get_file(file) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: file
      type(c_ptr) soup_request_file_get_file
    end function soup_request_file_get_file

    function soup_request_http_get_message(http) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: http
      type(c_ptr) soup_request_http_get_message
    end function soup_request_http_get_message

    function soup_requester_new() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_requester_new
    end function soup_requester_new

    function soup_requester_request( &
        requester, &
        uri_string, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: requester
      type(c_ptr), value :: uri_string
      type(c_ptr), value :: error
      type(c_ptr) soup_requester_request
    end function soup_requester_request

    function soup_requester_request_uri( &
        requester, &
        uri, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: requester
      type(c_ptr), value :: uri
      type(c_ptr), value :: error
      type(c_ptr) soup_requester_request_uri
    end function soup_requester_request_uri

    function soup_requester_error_quark() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_requester_error_quark
    end function soup_requester_error_quark

    function soup_server_new( &
        optname1, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: optname1
      type(c_ptr), value :: varargs
      type(c_ptr) soup_server_new
    end function soup_server_new

    function soup_server_accept_iostream( &
        server, &
        stream, &
        local_addr, &
        remote_addr, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: server
      type(c_ptr), value :: stream
      type(c_ptr), value :: local_addr
      type(c_ptr), value :: remote_addr
      type(c_ptr), value :: error
      logical(c_bool) soup_server_accept_iostream
    end function soup_server_accept_iostream

    subroutine soup_server_add_auth_domain( &
        server, &
        auth_domain &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
      type(c_ptr), value :: auth_domain
    end subroutine soup_server_add_auth_domain

    subroutine soup_server_add_early_handler( &
        server, &
        path, &
        callback, &
        user_data, &
        destroy &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
      type(c_ptr), value :: path
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
      type(c_ptr), value :: destroy
    end subroutine soup_server_add_early_handler

    subroutine soup_server_add_handler( &
        server, &
        path, &
        callback, &
        user_data, &
        destroy &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
      type(c_ptr), value :: path
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
      type(c_ptr), value :: destroy
    end subroutine soup_server_add_handler

    subroutine soup_server_add_websocket_handler( &
        server, &
        path, &
        origin, &
        protocols, &
        callback, &
        user_data, &
        destroy &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
      type(c_ptr), value :: path
      type(c_ptr), value :: origin
      type(c_ptr), value :: protocols
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
      type(c_ptr), value :: destroy
    end subroutine soup_server_add_websocket_handler

    subroutine soup_server_disconnect(server) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
    end subroutine soup_server_disconnect

    function soup_server_get_async_context(server) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
      type(c_ptr) soup_server_get_async_context
    end function soup_server_get_async_context

    function soup_server_get_listener(server) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
      type(c_ptr) soup_server_get_listener
    end function soup_server_get_listener

    function soup_server_get_listeners(server) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
      type(c_ptr) soup_server_get_listeners
    end function soup_server_get_listeners

    function soup_server_get_port(server) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: server
      integer(c_int) soup_server_get_port
    end function soup_server_get_port

    function soup_server_get_uris(server) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
      type(c_ptr) soup_server_get_uris
    end function soup_server_get_uris

    function soup_server_is_https(server) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: server
      logical(c_bool) soup_server_is_https
    end function soup_server_is_https

    function soup_server_listen( &
        server, &
        address, &
        options, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_int, c_ptr
      type(c_ptr), value :: server
      type(c_ptr), value :: address
      integer(c_int), value :: options
      type(c_ptr), value :: error
      logical(c_bool) soup_server_listen
    end function soup_server_listen

    function soup_server_listen_all( &
        server, &
        port, &
        options, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_int, c_ptr
      type(c_ptr), value :: server
      integer(c_int), value :: port
      integer(c_int), value :: options
      type(c_ptr), value :: error
      logical(c_bool) soup_server_listen_all
    end function soup_server_listen_all

    function soup_server_listen_fd( &
        server, &
        fd, &
        options, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_int, c_ptr
      type(c_ptr), value :: server
      type(c_ptr), value :: fd
      integer(c_int), value :: options
      type(c_ptr), value :: error
      logical(c_bool) soup_server_listen_fd
    end function soup_server_listen_fd

    function soup_server_listen_local( &
        server, &
        port, &
        options, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_int, c_ptr
      type(c_ptr), value :: server
      integer(c_int), value :: port
      integer(c_int), value :: options
      type(c_ptr), value :: error
      logical(c_bool) soup_server_listen_local
    end function soup_server_listen_local

    function soup_server_listen_socket( &
        server, &
        socket, &
        options, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_int, c_ptr
      type(c_ptr), value :: server
      type(c_ptr), value :: socket
      integer(c_int), value :: options
      type(c_ptr), value :: error
      logical(c_bool) soup_server_listen_socket
    end function soup_server_listen_socket

    subroutine soup_server_pause_message( &
        server, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
      type(c_ptr), value :: msg
    end subroutine soup_server_pause_message

    subroutine soup_server_quit(server) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
    end subroutine soup_server_quit

    subroutine soup_server_remove_auth_domain( &
        server, &
        auth_domain &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
      type(c_ptr), value :: auth_domain
    end subroutine soup_server_remove_auth_domain

    subroutine soup_server_remove_handler( &
        server, &
        path &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
      type(c_ptr), value :: path
    end subroutine soup_server_remove_handler

    subroutine soup_server_run(server) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
    end subroutine soup_server_run

    subroutine soup_server_run_async(server) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
    end subroutine soup_server_run_async

    function soup_server_set_ssl_cert_file( &
        server, &
        ssl_cert_file, &
        ssl_key_file, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: server
      type(c_ptr), value :: ssl_cert_file
      type(c_ptr), value :: ssl_key_file
      type(c_ptr), value :: error
      logical(c_bool) soup_server_set_ssl_cert_file
    end function soup_server_set_ssl_cert_file

    subroutine soup_server_unpause_message( &
        server, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: server
      type(c_ptr), value :: msg
    end subroutine soup_server_unpause_message

    function soup_session_new() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_session_new
    end function soup_session_new

    function soup_session_new_with_options( &
        optname1, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: optname1
      type(c_ptr), value :: varargs
      type(c_ptr) soup_session_new_with_options
    end function soup_session_new_with_options

    subroutine soup_session_abort(session) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
    end subroutine soup_session_abort

    subroutine soup_session_add_feature( &
        session, &
        feature &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: feature
    end subroutine soup_session_add_feature

    subroutine soup_session_add_feature_by_type( &
        session, &
        feature_type &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: feature_type
    end subroutine soup_session_add_feature_by_type

    subroutine soup_session_cancel_message( &
        session, &
        msg, &
        status_code &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: msg
      integer(c_int), value :: status_code
    end subroutine soup_session_cancel_message

    function soup_session_get_async_context(session) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr) soup_session_get_async_context
    end function soup_session_get_async_context

    function soup_session_get_feature( &
        session, &
        feature_type &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: feature_type
      type(c_ptr) soup_session_get_feature
    end function soup_session_get_feature

    function soup_session_get_feature_for_message( &
        session, &
        feature_type, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: feature_type
      type(c_ptr), value :: msg
      type(c_ptr) soup_session_get_feature_for_message
    end function soup_session_get_feature_for_message

    function soup_session_get_features( &
        session, &
        feature_type &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: feature_type
      type(c_ptr) soup_session_get_features
    end function soup_session_get_features

    function soup_session_has_feature( &
        session, &
        feature_type &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: feature_type
      logical(c_bool) soup_session_has_feature
    end function soup_session_has_feature

    subroutine soup_session_pause_message( &
        session, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: msg
    end subroutine soup_session_pause_message

    subroutine soup_session_prefetch_dns( &
        session, &
        hostname, &
        cancellable, &
        callback, &
        user_data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: hostname
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
    end subroutine soup_session_prefetch_dns

    subroutine soup_session_prepare_for_uri( &
        session, &
        uri &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: uri
    end subroutine soup_session_prepare_for_uri

    subroutine soup_session_queue_message( &
        session, &
        msg, &
        callback, &
        user_data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: msg
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
    end subroutine soup_session_queue_message

    function soup_session_redirect_message( &
        session, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: msg
      logical(c_bool) soup_session_redirect_message
    end function soup_session_redirect_message

    subroutine soup_session_remove_feature( &
        session, &
        feature &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: feature
    end subroutine soup_session_remove_feature

    subroutine soup_session_remove_feature_by_type( &
        session, &
        feature_type &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: feature_type
    end subroutine soup_session_remove_feature_by_type

    function soup_session_request( &
        session, &
        uri_string, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: uri_string
      type(c_ptr), value :: error
      type(c_ptr) soup_session_request
    end function soup_session_request

    function soup_session_request_http( &
        session, &
        method, &
        uri_string, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: method
      type(c_ptr), value :: uri_string
      type(c_ptr), value :: error
      type(c_ptr) soup_session_request_http
    end function soup_session_request_http

    function soup_session_request_http_uri( &
        session, &
        method, &
        uri, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: method
      type(c_ptr), value :: uri
      type(c_ptr), value :: error
      type(c_ptr) soup_session_request_http_uri
    end function soup_session_request_http_uri

    function soup_session_request_uri( &
        session, &
        uri, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: uri
      type(c_ptr), value :: error
      type(c_ptr) soup_session_request_uri
    end function soup_session_request_uri

    subroutine soup_session_requeue_message( &
        session, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: msg
    end subroutine soup_session_requeue_message

    function soup_session_send( &
        session, &
        msg, &
        cancellable, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: msg
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: error
      type(c_ptr) soup_session_send
    end function soup_session_send

    subroutine soup_session_send_async( &
        session, &
        msg, &
        cancellable, &
        callback, &
        user_data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: msg
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
    end subroutine soup_session_send_async

    function soup_session_send_finish( &
        session, &
        result, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: result
      type(c_ptr), value :: error
      type(c_ptr) soup_session_send_finish
    end function soup_session_send_finish

    function soup_session_send_message( &
        session, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: msg
      integer(c_int) soup_session_send_message
    end function soup_session_send_message

    function soup_session_steal_connection( &
        session, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: msg
      type(c_ptr) soup_session_steal_connection
    end function soup_session_steal_connection

    subroutine soup_session_unpause_message( &
        session, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: msg
    end subroutine soup_session_unpause_message

    subroutine soup_session_websocket_connect_async( &
        session, &
        msg, &
        origin, &
        protocols, &
        cancellable, &
        callback, &
        user_data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: msg
      type(c_ptr), value :: origin
      type(c_ptr), value :: protocols
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
    end subroutine soup_session_websocket_connect_async

    function soup_session_websocket_connect_finish( &
        session, &
        result, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: result
      type(c_ptr), value :: error
      type(c_ptr) soup_session_websocket_connect_finish
    end function soup_session_websocket_connect_finish

    function soup_session_would_redirect( &
        session, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: session
      type(c_ptr), value :: msg
      logical(c_bool) soup_session_would_redirect
    end function soup_session_would_redirect

    function soup_session_async_new() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_session_async_new
    end function soup_session_async_new

    function soup_session_async_new_with_options( &
        optname1, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: optname1
      type(c_ptr), value :: varargs
      type(c_ptr) soup_session_async_new_with_options
    end function soup_session_async_new_with_options

    function soup_session_feature_add_feature( &
        feature, &
        type &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: feature
      type(c_ptr), value :: type
      logical(c_bool) soup_session_feature_add_feature
    end function soup_session_feature_add_feature

    subroutine soup_session_feature_attach( &
        feature, &
        session &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: feature
      type(c_ptr), value :: session
    end subroutine soup_session_feature_attach

    subroutine soup_session_feature_detach( &
        feature, &
        session &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: feature
      type(c_ptr), value :: session
    end subroutine soup_session_feature_detach

    function soup_session_feature_has_feature( &
        feature, &
        type &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: feature
      type(c_ptr), value :: type
      logical(c_bool) soup_session_feature_has_feature
    end function soup_session_feature_has_feature

    function soup_session_feature_remove_feature( &
        feature, &
        type &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: feature
      type(c_ptr), value :: type
      logical(c_bool) soup_session_feature_remove_feature
    end function soup_session_feature_remove_feature

    function soup_session_sync_new() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_session_sync_new
    end function soup_session_sync_new

    function soup_session_sync_new_with_options( &
        optname1, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: optname1
      type(c_ptr), value :: varargs
      type(c_ptr) soup_session_sync_new_with_options
    end function soup_session_sync_new_with_options

    function soup_socket_new( &
        optname1, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: optname1
      type(c_ptr), value :: varargs
      type(c_ptr) soup_socket_new
    end function soup_socket_new

    subroutine soup_socket_connect_async( &
        sock, &
        cancellable, &
        callback, &
        user_data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: sock
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: callback
      type(c_ptr), value :: user_data
    end subroutine soup_socket_connect_async

    function soup_socket_connect_sync( &
        sock, &
        cancellable &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: sock
      type(c_ptr), value :: cancellable
      integer(c_int) soup_socket_connect_sync
    end function soup_socket_connect_sync

    subroutine soup_socket_disconnect(sock) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: sock
    end subroutine soup_socket_disconnect

    function soup_socket_get_fd(sock) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: sock
      type(c_ptr) soup_socket_get_fd
    end function soup_socket_get_fd

    function soup_socket_get_local_address(sock) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: sock
      type(c_ptr) soup_socket_get_local_address
    end function soup_socket_get_local_address

    function soup_socket_get_remote_address(sock) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: sock
      type(c_ptr) soup_socket_get_remote_address
    end function soup_socket_get_remote_address

    function soup_socket_is_connected(sock) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: sock
      logical(c_bool) soup_socket_is_connected
    end function soup_socket_is_connected

    function soup_socket_is_ssl(sock) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: sock
      logical(c_bool) soup_socket_is_ssl
    end function soup_socket_is_ssl

    function soup_socket_listen(sock) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: sock
      logical(c_bool) soup_socket_listen
    end function soup_socket_listen

    function soup_socket_read( &
        sock, &
        buffer, &
        len, &
        nread, &
        cancellable, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_int, c_long, c_ptr
      type(c_ptr), value :: sock
      type(c_ptr), value :: buffer
      integer(c_long), value :: len
      type(c_ptr), value :: nread
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: error
      integer(c_int) soup_socket_read
    end function soup_socket_read

    function soup_socket_read_until( &
        sock, &
        buffer, &
        len, &
        boundary, &
        boundary_len, &
        nread, &
        got_boundary, &
        cancellable, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_int, c_long, c_ptr
      type(c_ptr), value :: sock
      type(c_ptr), value :: buffer
      integer(c_long), value :: len
      type(c_ptr), value :: boundary
      integer(c_long), value :: boundary_len
      type(c_ptr), value :: nread
      type(c_ptr), value :: got_boundary
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: error
      integer(c_int) soup_socket_read_until
    end function soup_socket_read_until

    function soup_socket_start_proxy_ssl( &
        sock, &
        ssl_host, &
        cancellable &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: sock
      type(c_ptr), value :: ssl_host
      type(c_ptr), value :: cancellable
      logical(c_bool) soup_socket_start_proxy_ssl
    end function soup_socket_start_proxy_ssl

    function soup_socket_start_ssl( &
        sock, &
        cancellable &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: sock
      type(c_ptr), value :: cancellable
      logical(c_bool) soup_socket_start_ssl
    end function soup_socket_start_ssl

    function soup_socket_write( &
        sock, &
        buffer, &
        len, &
        nwrote, &
        cancellable, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_int, c_long, c_ptr
      type(c_ptr), value :: sock
      type(c_ptr), value :: buffer
      integer(c_long), value :: len
      type(c_ptr), value :: nwrote
      type(c_ptr), value :: cancellable
      type(c_ptr), value :: error
      integer(c_int) soup_socket_write
    end function soup_socket_write

    function soup_status_get_phrase(status_code) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      integer(c_int), value :: status_code
      type(c_ptr) soup_status_get_phrase
    end function soup_status_get_phrase

    function soup_status_proxify(status_code) bind(c)
      use iso_c_binding, only: c_int
      integer(c_int), value :: status_code
      integer(c_int) soup_status_proxify
    end function soup_status_proxify

    function soup_tld_error_quark() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_tld_error_quark
    end function soup_tld_error_quark

    function soup_uri_new(uri_string) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri_string
      type(c_ptr) soup_uri_new
    end function soup_uri_new

    function soup_uri_copy(uri) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr) soup_uri_copy
    end function soup_uri_copy

    function soup_uri_copy_host(uri) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr) soup_uri_copy_host
    end function soup_uri_copy_host

    function soup_uri_equal( &
        uri1, &
        uri2 &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: uri1
      type(c_ptr), value :: uri2
      logical(c_bool) soup_uri_equal
    end function soup_uri_equal

    subroutine soup_uri_free(uri) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
    end subroutine soup_uri_free

    function soup_uri_get_fragment(uri) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr) soup_uri_get_fragment
    end function soup_uri_get_fragment

    function soup_uri_get_host(uri) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr) soup_uri_get_host
    end function soup_uri_get_host

    function soup_uri_get_password(uri) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr) soup_uri_get_password
    end function soup_uri_get_password

    function soup_uri_get_path(uri) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr) soup_uri_get_path
    end function soup_uri_get_path

    function soup_uri_get_port(uri) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: uri
      integer(c_int) soup_uri_get_port
    end function soup_uri_get_port

    function soup_uri_get_query(uri) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr) soup_uri_get_query
    end function soup_uri_get_query

    function soup_uri_get_scheme(uri) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr) soup_uri_get_scheme
    end function soup_uri_get_scheme

    function soup_uri_get_user(uri) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr) soup_uri_get_user
    end function soup_uri_get_user

    function soup_uri_host_equal( &
        v1, &
        v2 &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: v1
      type(c_ptr), value :: v2
      logical(c_bool) soup_uri_host_equal
    end function soup_uri_host_equal

    function soup_uri_host_hash(key) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: key
      integer(c_int) soup_uri_host_hash
    end function soup_uri_host_hash

    function soup_uri_new_with_base( &
        base, &
        uri_string &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: base
      type(c_ptr), value :: uri_string
      type(c_ptr) soup_uri_new_with_base
    end function soup_uri_new_with_base

    subroutine soup_uri_set_fragment( &
        uri, &
        fragment &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr), value :: fragment
    end subroutine soup_uri_set_fragment

    subroutine soup_uri_set_host( &
        uri, &
        host &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr), value :: host
    end subroutine soup_uri_set_host

    subroutine soup_uri_set_password( &
        uri, &
        password &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr), value :: password
    end subroutine soup_uri_set_password

    subroutine soup_uri_set_path( &
        uri, &
        path &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr), value :: path
    end subroutine soup_uri_set_path

    subroutine soup_uri_set_port( &
        uri, &
        port &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: uri
      integer(c_int), value :: port
    end subroutine soup_uri_set_port

    subroutine soup_uri_set_query( &
        uri, &
        query &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr), value :: query
    end subroutine soup_uri_set_query

    subroutine soup_uri_set_query_from_fields( &
        uri, &
        first_field, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr), value :: first_field
      type(c_ptr), value :: varargs
    end subroutine soup_uri_set_query_from_fields

    subroutine soup_uri_set_query_from_form( &
        uri, &
        form &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr), value :: form
    end subroutine soup_uri_set_query_from_form

    subroutine soup_uri_set_scheme( &
        uri, &
        scheme &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr), value :: scheme
    end subroutine soup_uri_set_scheme

    subroutine soup_uri_set_user( &
        uri, &
        user &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr), value :: user
    end subroutine soup_uri_set_user

    function soup_uri_to_string( &
        uri, &
        just_path_and_query &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: uri
      logical(c_bool), value :: just_path_and_query
      type(c_ptr) soup_uri_to_string
    end function soup_uri_to_string

    function soup_uri_uses_default_port(uri) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: uri
      logical(c_bool) soup_uri_uses_default_port
    end function soup_uri_uses_default_port

    function soup_uri_decode(part) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: part
      type(c_ptr) soup_uri_decode
    end function soup_uri_decode

    function soup_uri_encode( &
        part, &
        escape_extra &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: part
      type(c_ptr), value :: escape_extra
      type(c_ptr) soup_uri_encode
    end function soup_uri_encode

    function soup_uri_normalize( &
        part, &
        unescape_extra &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: part
      type(c_ptr), value :: unescape_extra
      type(c_ptr) soup_uri_normalize
    end function soup_uri_normalize

    function soup_websocket_connection_new( &
        stream, &
        uri, &
        type, &
        origin, &
        protocol &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: stream
      type(c_ptr), value :: uri
      integer(c_int), value :: type
      type(c_ptr), value :: origin
      type(c_ptr), value :: protocol
      type(c_ptr) soup_websocket_connection_new
    end function soup_websocket_connection_new

    subroutine soup_websocket_connection_close( &
        self, &
        code, &
        data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: self
      type(c_ptr), value :: code
      type(c_ptr), value :: data
    end subroutine soup_websocket_connection_close

    function soup_websocket_connection_get_close_code(self) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: self
      type(c_ptr) soup_websocket_connection_get_close_code
    end function soup_websocket_connection_get_close_code

    function soup_websocket_connection_get_close_data(self) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: self
      type(c_ptr) soup_websocket_connection_get_close_data
    end function soup_websocket_connection_get_close_data

    function soup_websocket_connection_get_connection_type(self) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: self
      integer(c_int) soup_websocket_connection_get_connection_type
    end function soup_websocket_connection_get_connection_type

    function soup_websocket_connection_get_io_stream(self) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: self
      type(c_ptr) soup_websocket_connection_get_io_stream
    end function soup_websocket_connection_get_io_stream

    function soup_websocket_connection_get_keepalive_interval(self) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: self
      integer(c_int) soup_websocket_connection_get_keepalive_interval
    end function soup_websocket_connection_get_keepalive_interval

    function soup_websocket_connection_get_max_incoming_payload_size(self) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: self
      type(c_ptr) soup_websocket_connection_get_max_incoming_payload_size
    end function soup_websocket_connection_get_max_incoming_payload_size

    function soup_websocket_connection_get_origin(self) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: self
      type(c_ptr) soup_websocket_connection_get_origin
    end function soup_websocket_connection_get_origin

    function soup_websocket_connection_get_protocol(self) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: self
      type(c_ptr) soup_websocket_connection_get_protocol
    end function soup_websocket_connection_get_protocol

    function soup_websocket_connection_get_state(self) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: self
      integer(c_int) soup_websocket_connection_get_state
    end function soup_websocket_connection_get_state

    function soup_websocket_connection_get_uri(self) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: self
      type(c_ptr) soup_websocket_connection_get_uri
    end function soup_websocket_connection_get_uri

    subroutine soup_websocket_connection_send_binary( &
        self, &
        data, &
        length &
    ) bind(c)
      use iso_c_binding, only: c_long, c_ptr
      type(c_ptr), value :: self
      type(c_ptr), value :: data
      integer(c_long), value :: length
    end subroutine soup_websocket_connection_send_binary

    subroutine soup_websocket_connection_send_text( &
        self, &
        text &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: self
      type(c_ptr), value :: text
    end subroutine soup_websocket_connection_send_text

    subroutine soup_websocket_connection_set_keepalive_interval( &
        self, &
        interval &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: self
      integer(c_int), value :: interval
    end subroutine soup_websocket_connection_set_keepalive_interval

    subroutine soup_websocket_connection_set_max_incoming_payload_size( &
        self, &
        max_incoming_payload_size &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: self
      type(c_ptr), value :: max_incoming_payload_size
    end subroutine soup_websocket_connection_set_max_incoming_payload_size

    function soup_websocket_error_get_quark() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_websocket_error_get_quark
    end function soup_websocket_error_get_quark

    function soup_xmlrpc_error_quark() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_xmlrpc_error_quark
    end function soup_xmlrpc_error_quark

    function soup_xmlrpc_fault_quark() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_xmlrpc_fault_quark
    end function soup_xmlrpc_fault_quark

    subroutine soup_xmlrpc_params_free(self) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: self
    end subroutine soup_xmlrpc_params_free

    function soup_xmlrpc_params_parse( &
        self, &
        signature, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: self
      type(c_ptr), value :: signature
      type(c_ptr), value :: error
      type(c_ptr) soup_xmlrpc_params_parse
    end function soup_xmlrpc_params_parse

    function soup_add_completion( &
        async_context, &
        function, &
        data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: async_context
      type(c_ptr), value :: function
      type(c_ptr), value :: data
      type(c_ptr) soup_add_completion
    end function soup_add_completion

    function soup_add_idle( &
        async_context, &
        function, &
        data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: async_context
      type(c_ptr), value :: function
      type(c_ptr), value :: data
      type(c_ptr) soup_add_idle
    end function soup_add_idle

    function soup_add_io_watch( &
        async_context, &
        chan, &
        condition, &
        function, &
        data &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: async_context
      type(c_ptr), value :: chan
      type(c_ptr), value :: condition
      type(c_ptr), value :: function
      type(c_ptr), value :: data
      type(c_ptr) soup_add_io_watch
    end function soup_add_io_watch

    function soup_add_timeout( &
        async_context, &
        interval, &
        function, &
        data &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: async_context
      integer(c_int), value :: interval
      type(c_ptr), value :: function
      type(c_ptr), value :: data
      type(c_ptr) soup_add_timeout
    end function soup_add_timeout

    function soup_check_version( &
        major, &
        minor, &
        micro &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_int
      integer(c_int), value :: major
      integer(c_int), value :: minor
      integer(c_int), value :: micro
      logical(c_bool) soup_check_version
    end function soup_check_version

    subroutine soup_cookies_free(cookies) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookies
    end subroutine soup_cookies_free

    function soup_cookies_from_request(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr) soup_cookies_from_request
    end function soup_cookies_from_request

    function soup_cookies_from_response(msg) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr) soup_cookies_from_response
    end function soup_cookies_from_response

    function soup_cookies_to_cookie_header(cookies) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookies
      type(c_ptr) soup_cookies_to_cookie_header
    end function soup_cookies_to_cookie_header

    subroutine soup_cookies_to_request( &
        cookies, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookies
      type(c_ptr), value :: msg
    end subroutine soup_cookies_to_request

    subroutine soup_cookies_to_response( &
        cookies, &
        msg &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: cookies
      type(c_ptr), value :: msg
    end subroutine soup_cookies_to_response

    function soup_form_decode(encoded_form) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: encoded_form
      type(c_ptr) soup_form_decode
    end function soup_form_decode

    function soup_form_decode_multipart( &
        msg, &
        file_control_name, &
        filename, &
        content_type, &
        file &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: file_control_name
      type(c_ptr), value :: filename
      type(c_ptr), value :: content_type
      type(c_ptr), value :: file
      type(c_ptr) soup_form_decode_multipart
    end function soup_form_decode_multipart

    function soup_form_encode( &
        first_field, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: first_field
      type(c_ptr), value :: varargs
      type(c_ptr) soup_form_encode
    end function soup_form_encode

    function soup_form_encode_datalist(form_data_set) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: form_data_set
      type(c_ptr) soup_form_encode_datalist
    end function soup_form_encode_datalist

    function soup_form_encode_hash(form_data_set) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: form_data_set
      type(c_ptr) soup_form_encode_hash
    end function soup_form_encode_hash

    function soup_form_encode_valist( &
        first_field, &
        args &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: first_field
      type(c_ptr), value :: args
      type(c_ptr) soup_form_encode_valist
    end function soup_form_encode_valist

    function soup_form_request_new( &
        method, &
        uri, &
        first_field, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: method
      type(c_ptr), value :: uri
      type(c_ptr), value :: first_field
      type(c_ptr), value :: varargs
      type(c_ptr) soup_form_request_new
    end function soup_form_request_new

    function soup_form_request_new_from_datalist( &
        method, &
        uri, &
        form_data_set &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: method
      type(c_ptr), value :: uri
      type(c_ptr), value :: form_data_set
      type(c_ptr) soup_form_request_new_from_datalist
    end function soup_form_request_new_from_datalist

    function soup_form_request_new_from_hash( &
        method, &
        uri, &
        form_data_set &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: method
      type(c_ptr), value :: uri
      type(c_ptr), value :: form_data_set
      type(c_ptr) soup_form_request_new_from_hash
    end function soup_form_request_new_from_hash

    function soup_form_request_new_from_multipart( &
        uri, &
        multipart &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr), value :: multipart
      type(c_ptr) soup_form_request_new_from_multipart
    end function soup_form_request_new_from_multipart

    function soup_get_major_version() bind(c)
      use iso_c_binding, only: c_int
      integer(c_int) soup_get_major_version
    end function soup_get_major_version

    function soup_get_micro_version() bind(c)
      use iso_c_binding, only: c_int
      integer(c_int) soup_get_micro_version
    end function soup_get_micro_version

    function soup_get_minor_version() bind(c)
      use iso_c_binding, only: c_int
      integer(c_int) soup_get_minor_version
    end function soup_get_minor_version

    function soup_header_contains( &
        header, &
        token &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: header
      type(c_ptr), value :: token
      logical(c_bool) soup_header_contains
    end function soup_header_contains

    subroutine soup_header_free_list(list) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: list
    end subroutine soup_header_free_list

    subroutine soup_header_free_param_list(param_list) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: param_list
    end subroutine soup_header_free_param_list

    subroutine soup_header_g_string_append_param( &
        string, &
        name, &
        value &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: string
      type(c_ptr), value :: name
      type(c_ptr), value :: value
    end subroutine soup_header_g_string_append_param

    subroutine soup_header_g_string_append_param_quoted( &
        string, &
        name, &
        value &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: string
      type(c_ptr), value :: name
      type(c_ptr), value :: value
    end subroutine soup_header_g_string_append_param_quoted

    function soup_header_parse_list(header) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: header
      type(c_ptr) soup_header_parse_list
    end function soup_header_parse_list

    function soup_header_parse_param_list(header) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: header
      type(c_ptr) soup_header_parse_param_list
    end function soup_header_parse_param_list

    function soup_header_parse_quality_list( &
        header, &
        unacceptable &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: header
      type(c_ptr), value :: unacceptable
      type(c_ptr) soup_header_parse_quality_list
    end function soup_header_parse_quality_list

    function soup_header_parse_semi_param_list(header) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: header
      type(c_ptr) soup_header_parse_semi_param_list
    end function soup_header_parse_semi_param_list

    function soup_headers_parse( &
        str, &
        len, &
        dest &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: str
      type(c_ptr), value :: len
      type(c_ptr), value :: dest
      logical(c_bool) soup_headers_parse
    end function soup_headers_parse

    function soup_headers_parse_request( &
        str, &
        len, &
        req_headers, &
        req_method, &
        req_path, &
        ver &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: str
      type(c_ptr), value :: len
      type(c_ptr), value :: req_headers
      type(c_ptr), value :: req_method
      type(c_ptr), value :: req_path
      type(c_ptr), value :: ver
      integer(c_int) soup_headers_parse_request
    end function soup_headers_parse_request

    function soup_headers_parse_response( &
        str, &
        len, &
        headers, &
        ver, &
        status_code, &
        reason_phrase &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: str
      type(c_ptr), value :: len
      type(c_ptr), value :: headers
      type(c_ptr), value :: ver
      type(c_ptr), value :: status_code
      type(c_ptr), value :: reason_phrase
      logical(c_bool) soup_headers_parse_response
    end function soup_headers_parse_response

    function soup_headers_parse_status_line( &
        status_line, &
        ver, &
        status_code, &
        reason_phrase &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: status_line
      type(c_ptr), value :: ver
      type(c_ptr), value :: status_code
      type(c_ptr), value :: reason_phrase
      logical(c_bool) soup_headers_parse_status_line
    end function soup_headers_parse_status_line

    function soup_http_error_quark() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_http_error_quark
    end function soup_http_error_quark

    function soup_str_case_equal( &
        v1, &
        v2 &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: v1
      type(c_ptr), value :: v2
      logical(c_bool) soup_str_case_equal
    end function soup_str_case_equal

    function soup_str_case_hash(key) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: key
      integer(c_int) soup_str_case_hash
    end function soup_str_case_hash

    function soup_tld_domain_is_public_suffix(domain) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: domain
      logical(c_bool) soup_tld_domain_is_public_suffix
    end function soup_tld_domain_is_public_suffix

    function soup_tld_get_base_domain( &
        hostname, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hostname
      type(c_ptr), value :: error
      type(c_ptr) soup_tld_get_base_domain
    end function soup_tld_get_base_domain

    subroutine soup_value_array_append( &
        array, &
        type, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: array
      type(c_ptr), value :: type
      type(c_ptr), value :: varargs
    end subroutine soup_value_array_append

    subroutine soup_value_array_append_vals( &
        array, &
        first_type, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: array
      type(c_ptr), value :: first_type
      type(c_ptr), value :: varargs
    end subroutine soup_value_array_append_vals

    function soup_value_array_from_args(args) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: args
      type(c_ptr) soup_value_array_from_args
    end function soup_value_array_from_args

    function soup_value_array_get_nth( &
        array, &
        index_, &
        type, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_int, c_ptr
      type(c_ptr), value :: array
      integer(c_int), value :: index_
      type(c_ptr), value :: type
      type(c_ptr), value :: varargs
      logical(c_bool) soup_value_array_get_nth
    end function soup_value_array_get_nth

    subroutine soup_value_array_insert( &
        array, &
        index_, &
        type, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_int, c_ptr
      type(c_ptr), value :: array
      integer(c_int), value :: index_
      type(c_ptr), value :: type
      type(c_ptr), value :: varargs
    end subroutine soup_value_array_insert

    function soup_value_array_new() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_value_array_new
    end function soup_value_array_new

    function soup_value_array_new_with_vals( &
        first_type, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: first_type
      type(c_ptr), value :: varargs
      type(c_ptr) soup_value_array_new_with_vals
    end function soup_value_array_new_with_vals

    function soup_value_array_to_args( &
        array, &
        args &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: array
      type(c_ptr), value :: args
      logical(c_bool) soup_value_array_to_args
    end function soup_value_array_to_args

    subroutine soup_value_hash_insert( &
        hash, &
        key, &
        type, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hash
      type(c_ptr), value :: key
      type(c_ptr), value :: type
      type(c_ptr), value :: varargs
    end subroutine soup_value_hash_insert

    subroutine soup_value_hash_insert_vals( &
        hash, &
        first_key, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hash
      type(c_ptr), value :: first_key
      type(c_ptr), value :: varargs
    end subroutine soup_value_hash_insert_vals

    subroutine soup_value_hash_insert_value( &
        hash, &
        key, &
        value &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: hash
      type(c_ptr), value :: key
      type(c_ptr), value :: value
    end subroutine soup_value_hash_insert_value

    function soup_value_hash_lookup( &
        hash, &
        key, &
        type, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: hash
      type(c_ptr), value :: key
      type(c_ptr), value :: type
      type(c_ptr), value :: varargs
      logical(c_bool) soup_value_hash_lookup
    end function soup_value_hash_lookup

    function soup_value_hash_lookup_vals( &
        hash, &
        first_key, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: hash
      type(c_ptr), value :: first_key
      type(c_ptr), value :: varargs
      logical(c_bool) soup_value_hash_lookup_vals
    end function soup_value_hash_lookup_vals

    function soup_value_hash_new() bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr) soup_value_hash_new
    end function soup_value_hash_new

    function soup_value_hash_new_with_vals( &
        first_key, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: first_key
      type(c_ptr), value :: varargs
      type(c_ptr) soup_value_hash_new_with_vals
    end function soup_value_hash_new_with_vals

    subroutine soup_websocket_client_prepare_handshake( &
        msg, &
        origin, &
        protocols &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: origin
      type(c_ptr), value :: protocols
    end subroutine soup_websocket_client_prepare_handshake

    function soup_websocket_client_verify_handshake( &
        msg, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: error
      logical(c_bool) soup_websocket_client_verify_handshake
    end function soup_websocket_client_verify_handshake

    function soup_websocket_server_check_handshake( &
        msg, &
        origin, &
        protocols, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: origin
      type(c_ptr), value :: protocols
      type(c_ptr), value :: error
      logical(c_bool) soup_websocket_server_check_handshake
    end function soup_websocket_server_check_handshake

    function soup_websocket_server_process_handshake( &
        msg, &
        expected_origin, &
        protocols &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: expected_origin
      type(c_ptr), value :: protocols
      logical(c_bool) soup_websocket_server_process_handshake
    end function soup_websocket_server_process_handshake

    function soup_xmlrpc_build_fault( &
        fault_code, &
        fault_format, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: fault_code
      type(c_ptr), value :: fault_format
      type(c_ptr), value :: varargs
      type(c_ptr) soup_xmlrpc_build_fault
    end function soup_xmlrpc_build_fault

    function soup_xmlrpc_build_method_call( &
        method_name, &
        params, &
        n_params &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: method_name
      type(c_ptr), value :: params
      type(c_ptr), value :: n_params
      type(c_ptr) soup_xmlrpc_build_method_call
    end function soup_xmlrpc_build_method_call

    function soup_xmlrpc_build_method_response(value) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: value
      type(c_ptr) soup_xmlrpc_build_method_response
    end function soup_xmlrpc_build_method_response

    function soup_xmlrpc_build_request( &
        method_name, &
        params, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: method_name
      type(c_ptr), value :: params
      type(c_ptr), value :: error
      type(c_ptr) soup_xmlrpc_build_request
    end function soup_xmlrpc_build_request

    function soup_xmlrpc_build_response( &
        value, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: value
      type(c_ptr), value :: error
      type(c_ptr) soup_xmlrpc_build_response
    end function soup_xmlrpc_build_response

    function soup_xmlrpc_extract_method_call( &
        method_call, &
        length, &
        method_name, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: method_call
      type(c_ptr), value :: length
      type(c_ptr), value :: method_name
      type(c_ptr), value :: varargs
      logical(c_bool) soup_xmlrpc_extract_method_call
    end function soup_xmlrpc_extract_method_call

    function soup_xmlrpc_extract_method_response( &
        method_response, &
        length, &
        error, &
        type, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: method_response
      type(c_ptr), value :: length
      type(c_ptr), value :: error
      type(c_ptr), value :: type
      type(c_ptr), value :: varargs
      logical(c_bool) soup_xmlrpc_extract_method_response
    end function soup_xmlrpc_extract_method_response

    function soup_xmlrpc_message_new( &
        uri, &
        method_name, &
        params, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr), value :: method_name
      type(c_ptr), value :: params
      type(c_ptr), value :: error
      type(c_ptr) soup_xmlrpc_message_new
    end function soup_xmlrpc_message_new

    subroutine soup_xmlrpc_message_set_fault( &
        msg, &
        fault_code, &
        fault_format, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: fault_code
      type(c_ptr), value :: fault_format
      type(c_ptr), value :: varargs
    end subroutine soup_xmlrpc_message_set_fault

    function soup_xmlrpc_message_set_response( &
        msg, &
        value, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: value
      type(c_ptr), value :: error
      logical(c_bool) soup_xmlrpc_message_set_response
    end function soup_xmlrpc_message_set_response

    function soup_xmlrpc_parse_method_call( &
        method_call, &
        length, &
        method_name, &
        params &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: method_call
      type(c_ptr), value :: length
      type(c_ptr), value :: method_name
      type(c_ptr), value :: params
      logical(c_bool) soup_xmlrpc_parse_method_call
    end function soup_xmlrpc_parse_method_call

    function soup_xmlrpc_parse_method_response( &
        method_response, &
        length, &
        value, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_bool, c_ptr
      type(c_ptr), value :: method_response
      type(c_ptr), value :: length
      type(c_ptr), value :: value
      type(c_ptr), value :: error
      logical(c_bool) soup_xmlrpc_parse_method_response
    end function soup_xmlrpc_parse_method_response

    function soup_xmlrpc_parse_request( &
        method_call, &
        length, &
        params, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: method_call
      type(c_ptr), value :: length
      type(c_ptr), value :: params
      type(c_ptr), value :: error
      type(c_ptr) soup_xmlrpc_parse_request
    end function soup_xmlrpc_parse_request

    function soup_xmlrpc_parse_response( &
        method_response, &
        length, &
        signature, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: method_response
      type(c_ptr), value :: length
      type(c_ptr), value :: signature
      type(c_ptr), value :: error
      type(c_ptr) soup_xmlrpc_parse_response
    end function soup_xmlrpc_parse_response

    function soup_xmlrpc_request_new( &
        uri, &
        method_name, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: uri
      type(c_ptr), value :: method_name
      type(c_ptr), value :: varargs
      type(c_ptr) soup_xmlrpc_request_new
    end function soup_xmlrpc_request_new

    subroutine soup_xmlrpc_set_fault( &
        msg, &
        fault_code, &
        fault_format, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: fault_code
      type(c_ptr), value :: fault_format
      type(c_ptr), value :: varargs
    end subroutine soup_xmlrpc_set_fault

    subroutine soup_xmlrpc_set_response( &
        msg, &
        type, &
        varargs &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: msg
      type(c_ptr), value :: type
      type(c_ptr), value :: varargs
    end subroutine soup_xmlrpc_set_response

    function soup_xmlrpc_variant_get_datetime( &
        variant, &
        error &
    ) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: variant
      type(c_ptr), value :: error
      type(c_ptr) soup_xmlrpc_variant_get_datetime
    end function soup_xmlrpc_variant_get_datetime

    function soup_xmlrpc_variant_new_datetime(date) bind(c)
      use iso_c_binding, only: c_ptr
      type(c_ptr), value :: date
      type(c_ptr) soup_xmlrpc_variant_new_datetime
    end function soup_xmlrpc_variant_new_datetime

  end interface
end module soup
