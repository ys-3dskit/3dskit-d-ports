module ys3ds.curl;

import core.stdc.config;
import core.sys.horizon.sys.select;
import core.sys.horizon.sys.socket;

extern (C):

/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/*
 * If you have libcurl problems, all docs and details are found here:
 *   https://curl.se/libcurl/
 */

public import ys3ds.curl.curlver; /* libcurl version defines   */
public import ys3ds.curl.system;  /* determine things run-time */

alias CURL = void;
alias CURLSH = void;

/* socket typedef */

alias curl_socket_t = int;
enum CURL_SOCKET_BAD = -1;

/* curl_socket_typedef */

/* enum for the different supported SSL backends */
enum curl_sslbackend
{
    CURLSSLBACKEND_NONE = 0,
    CURLSSLBACKEND_OPENSSL = 1,
    CURLSSLBACKEND_GNUTLS = 2,
    deprecated CURLSSLBACKEND_NSS = 3,
    CURLSSLBACKEND_OBSOLETE4 = 4, /* Was QSOSSL. */
    deprecated CURLSSLBACKEND_GSKIT = 5,
    deprecated CURLSSLBACKEND_POLARSSL = 6,
    CURLSSLBACKEND_WOLFSSL = 7,
    CURLSSLBACKEND_SCHANNEL = 8,
    CURLSSLBACKEND_SECURETRANSPORT = 9,
    deprecated CURLSSLBACKEND_AXTLS = 10,
    CURLSSLBACKEND_MBEDTLS = 11,
    deprecated CURLSSLBACKEND_MESALINK = 12,
    CURLSSLBACKEND_BEARSSL = 13,
    CURLSSLBACKEND_RUSTLS = 14
}

/* aliases for library clones and renames */
enum CURLSSLBACKEND_AWSLC = curl_sslbackend.CURLSSLBACKEND_OPENSSL;
enum CURLSSLBACKEND_BORINGSSL = curl_sslbackend.CURLSSLBACKEND_OPENSSL;
enum CURLSSLBACKEND_LIBRESSL = curl_sslbackend.CURLSSLBACKEND_OPENSSL;

/* deprecated names: */
enum CURLSSLBACKEND_CYASSL = curl_sslbackend.CURLSSLBACKEND_WOLFSSL;
enum CURLSSLBACKEND_DARWINSSL = curl_sslbackend.CURLSSLBACKEND_SECURETRANSPORT;

struct curl_httppost
{
    curl_httppost* next; /* next entry in the list */
    char* name; /* pointer to allocated name */
    c_long namelength; /* length of name length */
    char* contents; /* pointer to allocated data contents */
    c_long contentslength; /* length of contents field, see also
       CURL_HTTPPOST_LARGE */
    char* buffer; /* pointer to allocated buffer contents */
    c_long bufferlength; /* length of buffer field */
    char* contenttype; /* Content-Type */
    curl_slist* contentheader; /* list of extra headers for this form */
    curl_httppost* more; /* if one field name has more than one
       file, this link should link to following
       files */
    c_long flags; /* as defined below */

    char* showfilename; /* The file name to show. If not set, the
       actual file name will be used (if this
       is a file part) */
    void* userp; /* custom pointer used for
       HTTPPOST_CALLBACK posts */
    curl_off_t contentlen; /* alternative length of contents
       field. Used if CURL_HTTPPOST_LARGE is
       set. Added in 7.46.0 */
}

/* specified content is a file name */
enum CURL_HTTPPOST_FILENAME = 1 << 0;
/* specified content is a file name */
enum CURL_HTTPPOST_READFILE = 1 << 1;
/* name is only stored pointer do not free in formfree */
enum CURL_HTTPPOST_PTRNAME = 1 << 2;
/* contents is only stored pointer do not free in formfree */
enum CURL_HTTPPOST_PTRCONTENTS = 1 << 3;
/* upload file from buffer */
enum CURL_HTTPPOST_BUFFER = 1 << 4;
/* upload file from pointer contents */
enum CURL_HTTPPOST_PTRBUFFER = 1 << 5;
/* upload file contents by using the regular read callback to get the data and
   pass the given pointer as custom pointer */
enum CURL_HTTPPOST_CALLBACK = 1 << 6;
/* use size in 'contentlen', added in 7.46.0 */
enum CURL_HTTPPOST_LARGE = 1 << 7;

/* This is a return code for the progress callback that, when returned, will
   signal libcurl to continue executing the default progress function */
enum CURL_PROGRESSFUNC_CONTINUE = 0x10000001;

/* This is the CURLOPT_PROGRESSFUNCTION callback prototype. It is now
   considered deprecated but was the only choice up until 7.31.0 */
alias curl_progress_callback = int function (
    void* clientp,
    double dltotal,
    double dlnow,
    double ultotal,
    double ulnow);

/* This is the CURLOPT_XFERINFOFUNCTION callback prototype. It was introduced
   in 7.32.0, avoids the use of floating point numbers and provides more
   detailed information. */
alias curl_xferinfo_callback = int function (
    void* clientp,
    curl_off_t dltotal,
    curl_off_t dlnow,
    curl_off_t ultotal,
    curl_off_t ulnow);

/* The maximum receive buffer size configurable via CURLOPT_BUFFERSIZE. */
enum CURL_MAX_READ_SIZE = 10 * 1024 * 1024;

/* Tests have proven that 20K is a very bad buffer size for uploads on
   Windows, while 16K for some odd reason performed a lot better.
   We do the ifndef check to allow this value to easier be changed at build
   time for those who feel adventurous. The practical minimum is about
   400 bytes since libcurl uses a buffer of this size as a scratch area
   (unrelated to network send operations). */
enum CURL_MAX_WRITE_SIZE = 16384;

/* The only reason to have a max limit for this is to avoid the risk of a bad
   server feeding libcurl with a never-ending header that will cause reallocs
   infinitely */
enum CURL_MAX_HTTP_HEADER = 100 * 1024;

/* This is a magic return code for the write callback that, when returned,
   will signal libcurl to pause receiving on the current transfer. */
enum CURL_WRITEFUNC_PAUSE = 0x10000001;

/* This is a magic return code for the write callback that, when returned,
   will signal an error from the callback. */
enum CURL_WRITEFUNC_ERROR = 0xFFFFFFFF;

alias curl_write_callback = c_ulong function (
    char* buffer,
    size_t size,
    size_t nitems,
    void* outstream);

/* This callback will be called when a new resolver request is made */
alias curl_resolver_start_callback = int function (
    void* resolver_state,
    void* reserved,
    void* userdata);

/* enumeration of file types */
enum curlfiletype
{
    CURLFILETYPE_FILE = 0,
    CURLFILETYPE_DIRECTORY = 1,
    CURLFILETYPE_SYMLINK = 2,
    CURLFILETYPE_DEVICE_BLOCK = 3,
    CURLFILETYPE_DEVICE_CHAR = 4,
    CURLFILETYPE_NAMEDPIPE = 5,
    CURLFILETYPE_SOCKET = 6,
    CURLFILETYPE_DOOR = 7, /* is possible only on Sun Solaris now */

    CURLFILETYPE_UNKNOWN = 8 /* should never occur */
}

enum CURLFINFOFLAG_KNOWN_FILENAME = 1 << 0;
enum CURLFINFOFLAG_KNOWN_FILETYPE = 1 << 1;
enum CURLFINFOFLAG_KNOWN_TIME = 1 << 2;
enum CURLFINFOFLAG_KNOWN_PERM = 1 << 3;
enum CURLFINFOFLAG_KNOWN_UID = 1 << 4;
enum CURLFINFOFLAG_KNOWN_GID = 1 << 5;
enum CURLFINFOFLAG_KNOWN_SIZE = 1 << 6;
enum CURLFINFOFLAG_KNOWN_HLINKCOUNT = 1 << 7;

/* Information about a single file, used when doing FTP wildcard matching */
struct curl_fileinfo
{
    char* filename;
    curlfiletype filetype;
    time_t time; /* always zero! */
    uint perm;
    int uid;
    int gid;
    curl_off_t size;
    c_long hardlinks;

    /* If some of these fields is not NULL, it is a pointer to b_data. */

    /* pointer to the target filename of a symlink */
    struct _Anonymous_0
    {
        char* time;
        char* perm;
        char* user;
        char* group;
        char* target;
    }

    _Anonymous_0 strings;

    uint flags;

    /* These are libcurl private struct fields. Previously used by libcurl, so
       they must never be interfered with. */
    char* b_data;
    size_t b_size;
    size_t b_used;
}

/* return codes for CURLOPT_CHUNK_BGN_FUNCTION */
enum CURL_CHUNK_BGN_FUNC_OK = 0;
enum CURL_CHUNK_BGN_FUNC_FAIL = 1; /* tell the lib to end the task */
enum CURL_CHUNK_BGN_FUNC_SKIP = 2; /* skip this chunk over */

/* if splitting of data transfer is enabled, this callback is called before
   download of an individual chunk started. Note that parameter "remains" works
   only for FTP wildcard downloading (for now), otherwise is not used */
alias curl_chunk_bgn_callback = c_long function (
    const(void)* transfer_info,
    void* ptr,
    int remains);

/* return codes for CURLOPT_CHUNK_END_FUNCTION */
enum CURL_CHUNK_END_FUNC_OK = 0;
enum CURL_CHUNK_END_FUNC_FAIL = 1; /* tell the lib to end the task */

/* If splitting of data transfer is enabled this callback is called after
   download of an individual chunk finished.
   Note! After this callback was set then it have to be called FOR ALL chunks.
   Even if downloading of this chunk was skipped in CHUNK_BGN_FUNC.
   This is the reason why we don't need "transfer_info" parameter in this
   callback and we are not interested in "remains" parameter too. */
alias curl_chunk_end_callback = c_long function (void* ptr);

/* return codes for FNMATCHFUNCTION */
enum CURL_FNMATCHFUNC_MATCH = 0; /* string corresponds to the pattern */
enum CURL_FNMATCHFUNC_NOMATCH = 1; /* pattern doesn't match the string */
enum CURL_FNMATCHFUNC_FAIL = 2; /* an error occurred */

/* callback type for wildcard downloading pattern matching. If the
   string matches the pattern, return CURL_FNMATCHFUNC_MATCH value, etc. */
alias curl_fnmatch_callback = int function (
    void* ptr,
    const(char)* pattern,
    const(char)* string);

/* These are the return codes for the seek callbacks */
enum CURL_SEEKFUNC_OK = 0;
enum CURL_SEEKFUNC_FAIL = 1; /* fail the entire transfer */
enum CURL_SEEKFUNC_CANTSEEK = 2; /* tell libcurl seeking can't be done, so
   libcurl might try other means instead */
alias curl_seek_callback = int function (
    void* instream,
    curl_off_t offset,
    int origin); /* 'whence' */

/* This is a return code for the read callback that, when returned, will
   signal libcurl to immediately abort the current transfer. */
enum CURL_READFUNC_ABORT = 0x10000000;
/* This is a return code for the read callback that, when returned, will
   signal libcurl to pause sending data on the current transfer. */
enum CURL_READFUNC_PAUSE = 0x10000001;

/* Return code for when the trailing headers' callback has terminated
   without any errors */
enum CURL_TRAILERFUNC_OK = 0;
/* Return code for when was an error in the trailing header's list and we
  want to abort the request */
enum CURL_TRAILERFUNC_ABORT = 1;

alias curl_read_callback = c_ulong function (
    char* buffer,
    size_t size,
    size_t nitems,
    void* instream);

alias curl_trailer_callback = int function (curl_slist** list, void* userdata);

enum curlsocktype
{
    CURLSOCKTYPE_IPCXN = 0, /* socket created for a specific IP connection */
    CURLSOCKTYPE_ACCEPT = 1, /* socket created by accept() call */
    CURLSOCKTYPE_LAST = 2 /* never use */
}

/* The return code from the sockopt_callback can signal information back
   to libcurl: */
enum CURL_SOCKOPT_OK = 0;
enum CURL_SOCKOPT_ERROR = 1; /* causes libcurl to abort and return
   CURLE_ABORTED_BY_CALLBACK */
enum CURL_SOCKOPT_ALREADY_CONNECTED = 2;

alias curl_sockopt_callback = int function (
    void* clientp,
    curl_socket_t curlfd,
    curlsocktype purpose);

struct curl_sockaddr
{
    int family;
    int socktype;
    int protocol;
    uint addrlen; /* addrlen was a socklen_t type before 7.18.0 but it
       turned really ugly and painful on the systems that
       lack this type */
    sockaddr addr;
}

alias curl_opensocket_callback = int function (
    void* clientp,
    curlsocktype purpose,
    curl_sockaddr* address);

alias curl_closesocket_callback = int function (
    void* clientp,
    curl_socket_t item);

enum curlioerr
{
    CURLIOE_OK = 0, /* I/O operation successful */
    CURLIOE_UNKNOWNCMD = 1, /* command was unknown to callback */
    CURLIOE_FAILRESTART = 2, /* failed to restart the read */
    CURLIOE_LAST = 3 /* never use */
}

enum curliocmd
{
    CURLIOCMD_NOP = 0, /* no operation */
    CURLIOCMD_RESTARTREAD = 1, /* restart the read stream from start */
    CURLIOCMD_LAST = 2 /* never use */
}

alias curl_ioctl_callback = curlioerr function (
    CURL* handle,
    int cmd,
    void* clientp);

/*
 * The following typedef's are signatures of malloc, free, realloc, strdup and
 * calloc respectively.  Function pointers of these types can be passed to the
 * curl_global_init_mem() function to set user defined memory management
 * callback routines.
 */
alias curl_malloc_callback = void* function (size_t size);
alias curl_free_callback = void function (void* ptr);
alias curl_realloc_callback = void* function (void* ptr, size_t size);
alias curl_strdup_callback = char* function (const(char)* str);
alias curl_calloc_callback = void* function (size_t nmemb, size_t size);

/* the kind of data that is passed to information_callback */
enum curl_infotype
{
    CURLINFO_TEXT = 0,
    CURLINFO_HEADER_IN = 1, /* 1 */
    CURLINFO_HEADER_OUT = 2, /* 2 */
    CURLINFO_DATA_IN = 3, /* 3 */
    CURLINFO_DATA_OUT = 4, /* 4 */
    CURLINFO_SSL_DATA_IN = 5, /* 5 */
    CURLINFO_SSL_DATA_OUT = 6, /* 6 */
    CURLINFO_END = 7
}

alias curl_debug_callback = int function (
    CURL* handle,       /* the handle/transfer this concerns */
    curl_infotype type, /* what kind of data */
    char* data,         /* points to the data */
    size_t size,        /* size of the data pointed to */
    void* userptr);     /* whatever the user please */

/* This is the CURLOPT_PREREQFUNCTION callback prototype. */
alias curl_prereq_callback = int function (
    void* clientp,
    char* conn_primary_ip,
    char* conn_local_ip,
    int conn_primary_port,
    int conn_local_port);

/* Return code for when the pre-request callback has terminated without
   any errors */
enum CURL_PREREQFUNC_OK = 0;
/* Return code for when the pre-request callback wants to abort the
   request */
enum CURL_PREREQFUNC_ABORT = 1;

/* All possible error codes from all sorts of curl functions. Future versions
   may return other values, stay prepared.

   Always add new return codes last. Never *EVER* remove any. The return
   codes must remain the same!
 */

enum CURLcode
{
    CURLE_OK = 0,
    CURLE_UNSUPPORTED_PROTOCOL = 1, /* 1 */
    CURLE_FAILED_INIT = 2, /* 2 */
    CURLE_URL_MALFORMAT = 3, /* 3 */
    CURLE_NOT_BUILT_IN = 4, /* 4 - [was obsoleted in August 2007 for
       7.17.0, reused in April 2011 for 7.21.5] */
    CURLE_COULDNT_RESOLVE_PROXY = 5, /* 5 */
    CURLE_COULDNT_RESOLVE_HOST = 6, /* 6 */
    CURLE_COULDNT_CONNECT = 7, /* 7 */
    CURLE_WEIRD_SERVER_REPLY = 8, /* 8 */
    CURLE_REMOTE_ACCESS_DENIED = 9, /* 9 a service was denied by the server
       due to lack of access - when login fails
       this is not returned. */
    CURLE_FTP_ACCEPT_FAILED = 10, /* 10 - [was obsoleted in April 2006 for
       7.15.4, reused in Dec 2011 for 7.24.0]*/
    CURLE_FTP_WEIRD_PASS_REPLY = 11, /* 11 */
    CURLE_FTP_ACCEPT_TIMEOUT = 12, /* 12 - timeout occurred accepting server
       [was obsoleted in August 2007 for 7.17.0,
       reused in Dec 2011 for 7.24.0]*/
    CURLE_FTP_WEIRD_PASV_REPLY = 13, /* 13 */
    CURLE_FTP_WEIRD_227_FORMAT = 14, /* 14 */
    CURLE_FTP_CANT_GET_HOST = 15, /* 15 */
    CURLE_HTTP2 = 16, /* 16 - A problem in the http2 framing layer.
       [was obsoleted in August 2007 for 7.17.0,
       reused in July 2014 for 7.38.0] */
    CURLE_FTP_COULDNT_SET_TYPE = 17, /* 17 */
    CURLE_PARTIAL_FILE = 18, /* 18 */
    CURLE_FTP_COULDNT_RETR_FILE = 19, /* 19 */
    CURLE_OBSOLETE20 = 20, /* 20 - NOT USED */
    CURLE_QUOTE_ERROR = 21, /* 21 - quote command failure */
    CURLE_HTTP_RETURNED_ERROR = 22, /* 22 */
    CURLE_WRITE_ERROR = 23, /* 23 */
    CURLE_OBSOLETE24 = 24, /* 24 - NOT USED */
    CURLE_UPLOAD_FAILED = 25, /* 25 - failed upload "command" */
    CURLE_READ_ERROR = 26, /* 26 - couldn't open/read from file */
    CURLE_OUT_OF_MEMORY = 27, /* 27 */
    CURLE_OPERATION_TIMEDOUT = 28, /* 28 - the timeout time was reached */
    CURLE_OBSOLETE29 = 29, /* 29 - NOT USED */
    CURLE_FTP_PORT_FAILED = 30, /* 30 - FTP PORT operation failed */
    CURLE_FTP_COULDNT_USE_REST = 31, /* 31 - the REST command failed */
    CURLE_OBSOLETE32 = 32, /* 32 - NOT USED */
    CURLE_RANGE_ERROR = 33, /* 33 - RANGE "command" didn't work */
    CURLE_HTTP_POST_ERROR = 34, /* 34 */
    CURLE_SSL_CONNECT_ERROR = 35, /* 35 - wrong when connecting with SSL */
    CURLE_BAD_DOWNLOAD_RESUME = 36, /* 36 - couldn't resume download */
    CURLE_FILE_COULDNT_READ_FILE = 37, /* 37 */
    CURLE_LDAP_CANNOT_BIND = 38, /* 38 */
    CURLE_LDAP_SEARCH_FAILED = 39, /* 39 */
    CURLE_OBSOLETE40 = 40, /* 40 - NOT USED */
    CURLE_FUNCTION_NOT_FOUND = 41, /* 41 - NOT USED starting with 7.53.0 */
    CURLE_ABORTED_BY_CALLBACK = 42, /* 42 */
    CURLE_BAD_FUNCTION_ARGUMENT = 43, /* 43 */
    CURLE_OBSOLETE44 = 44, /* 44 - NOT USED */
    CURLE_INTERFACE_FAILED = 45, /* 45 - CURLOPT_INTERFACE failed */
    CURLE_OBSOLETE46 = 46, /* 46 - NOT USED */
    CURLE_TOO_MANY_REDIRECTS = 47, /* 47 - catch endless re-direct loops */
    CURLE_UNKNOWN_OPTION = 48, /* 48 - User specified an unknown option */
    CURLE_SETOPT_OPTION_SYNTAX = 49, /* 49 - Malformed setopt option */
    CURLE_OBSOLETE50 = 50, /* 50 - NOT USED */
    CURLE_OBSOLETE51 = 51, /* 51 - NOT USED */
    CURLE_GOT_NOTHING = 52, /* 52 - when this is a specific error */
    CURLE_SSL_ENGINE_NOTFOUND = 53, /* 53 - SSL crypto engine not found */
    CURLE_SSL_ENGINE_SETFAILED = 54, /* 54 - can not set SSL crypto engine as
       default */
    CURLE_SEND_ERROR = 55, /* 55 - failed sending network data */
    CURLE_RECV_ERROR = 56, /* 56 - failure in receiving network data */
    CURLE_OBSOLETE57 = 57, /* 57 - NOT IN USE */
    CURLE_SSL_CERTPROBLEM = 58, /* 58 - problem with the local certificate */
    CURLE_SSL_CIPHER = 59, /* 59 - couldn't use specified cipher */
    CURLE_PEER_FAILED_VERIFICATION = 60, /* 60 - peer's certificate or fingerprint
       wasn't verified fine */
    CURLE_BAD_CONTENT_ENCODING = 61, /* 61 - Unrecognized/bad encoding */
    CURLE_OBSOLETE62 = 62, /* 62 - NOT IN USE since 7.82.0 */
    CURLE_FILESIZE_EXCEEDED = 63, /* 63 - Maximum file size exceeded */
    CURLE_USE_SSL_FAILED = 64, /* 64 - Requested FTP SSL level failed */
    CURLE_SEND_FAIL_REWIND = 65, /* 65 - Sending the data requires a rewind
       that failed */
    CURLE_SSL_ENGINE_INITFAILED = 66, /* 66 - failed to initialise ENGINE */
    CURLE_LOGIN_DENIED = 67, /* 67 - user, password or similar was not
       accepted and we failed to login */
    CURLE_TFTP_NOTFOUND = 68, /* 68 - file not found on server */
    CURLE_TFTP_PERM = 69, /* 69 - permission problem on server */
    CURLE_REMOTE_DISK_FULL = 70, /* 70 - out of disk space on server */
    CURLE_TFTP_ILLEGAL = 71, /* 71 - Illegal TFTP operation */
    CURLE_TFTP_UNKNOWNID = 72, /* 72 - Unknown transfer ID */
    CURLE_REMOTE_FILE_EXISTS = 73, /* 73 - File already exists */
    CURLE_TFTP_NOSUCHUSER = 74, /* 74 - No such user */
    CURLE_OBSOLETE75 = 75, /* 75 - NOT IN USE since 7.82.0 */
    CURLE_OBSOLETE76 = 76, /* 76 - NOT IN USE since 7.82.0 */
    CURLE_SSL_CACERT_BADFILE = 77, /* 77 - could not load CACERT file, missing
       or wrong format */
    CURLE_REMOTE_FILE_NOT_FOUND = 78, /* 78 - remote file not found */
    CURLE_SSH = 79, /* 79 - error from the SSH layer, somewhat
       generic so the error message will be of
       interest when this has happened */

    CURLE_SSL_SHUTDOWN_FAILED = 80, /* 80 - Failed to shut down the SSL
       connection */
    CURLE_AGAIN = 81, /* 81 - socket is not ready for send/recv,
       wait till it's ready and try again (Added
       in 7.18.2) */
    CURLE_SSL_CRL_BADFILE = 82, /* 82 - could not load CRL file, missing or
       wrong format (Added in 7.19.0) */
    CURLE_SSL_ISSUER_ERROR = 83, /* 83 - Issuer check failed.  (Added in
       7.19.0) */
    CURLE_FTP_PRET_FAILED = 84, /* 84 - a PRET command failed */
    CURLE_RTSP_CSEQ_ERROR = 85, /* 85 - mismatch of RTSP CSeq numbers */
    CURLE_RTSP_SESSION_ERROR = 86, /* 86 - mismatch of RTSP Session Ids */
    CURLE_FTP_BAD_FILE_LIST = 87, /* 87 - unable to parse FTP file list */
    CURLE_CHUNK_FAILED = 88, /* 88 - chunk callback reported error */
    CURLE_NO_CONNECTION_AVAILABLE = 89, /* 89 - No connection available, the
       session will be queued */
    CURLE_SSL_PINNEDPUBKEYNOTMATCH = 90, /* 90 - specified pinned public key did not
       match */
    CURLE_SSL_INVALIDCERTSTATUS = 91, /* 91 - invalid certificate status */
    CURLE_HTTP2_STREAM = 92, /* 92 - stream error in HTTP/2 framing layer
       */
    CURLE_RECURSIVE_API_CALL = 93, /* 93 - an api function was called from
       inside a callback */
    CURLE_AUTH_ERROR = 94, /* 94 - an authentication function returned an
       error */
    CURLE_HTTP3 = 95, /* 95 - An HTTP/3 layer problem */
    CURLE_QUIC_CONNECT_ERROR = 96, /* 96 - QUIC connection error */
    CURLE_PROXY = 97, /* 97 - proxy handshake error */
    CURLE_SSL_CLIENTCERT = 98, /* 98 - client-side certificate required */
    CURLE_UNRECOVERABLE_POLL = 99, /* 99 - poll/select returned fatal error */
    CURL_LAST /* never use! */
}

/* define CURL_NO_OLDIES to test if your app builds with all
   the obsolete stuff removed! */

/* Previously obsolete error code reused in 7.38.0 */
enum CURLE_OBSOLETE16 = CURLcode.CURLE_HTTP2;

/* Previously obsolete error codes reused in 7.24.0 */
enum CURLE_OBSOLETE10 = CURLcode.CURLE_FTP_ACCEPT_FAILED;
enum CURLE_OBSOLETE12 = CURLcode.CURLE_FTP_ACCEPT_TIMEOUT;

/*  compatibility with older names */
enum CURLOPT_ENCODING = CURLoption.CURLOPT_ACCEPT_ENCODING;
enum CURLE_FTP_WEIRD_SERVER_REPLY = CURLcode.CURLE_WEIRD_SERVER_REPLY;

/* The following were added in 7.62.0 */
enum CURLE_SSL_CACERT = CURLcode.CURLE_PEER_FAILED_VERIFICATION;

/* The following were added in 7.21.5, April 2011 */
enum CURLE_UNKNOWN_TELNET_OPTION = CURLcode.CURLE_UNKNOWN_OPTION;

/* Added for 7.78.0 */
enum CURLE_TELNET_OPTION_SYNTAX = CURLcode.CURLE_SETOPT_OPTION_SYNTAX;

/* The following were added in 7.17.1 */
/* These are scheduled to disappear by 2009 */
enum CURLE_SSL_PEER_CERTIFICATE = CURLcode.CURLE_PEER_FAILED_VERIFICATION;

/* The following were added in 7.17.0 */
/* These are scheduled to disappear by 2009 */
enum CURLE_OBSOLETE = CURLcode.CURLE_OBSOLETE50; /* no one should be using this! */
enum CURLE_BAD_PASSWORD_ENTERED = CURLcode.CURLE_OBSOLETE46;
enum CURLE_BAD_CALLING_ORDER = CURLcode.CURLE_OBSOLETE44;
enum CURLE_FTP_USER_PASSWORD_INCORRECT = CURLE_OBSOLETE10;
enum CURLE_FTP_CANT_RECONNECT = CURLE_OBSOLETE16;
enum CURLE_FTP_COULDNT_GET_SIZE = CURLcode.CURLE_OBSOLETE32;
enum CURLE_FTP_COULDNT_SET_ASCII = CURLcode.CURLE_OBSOLETE29;
enum CURLE_FTP_WEIRD_USER_REPLY = CURLE_OBSOLETE12;
enum CURLE_FTP_WRITE_ERROR = CURLcode.CURLE_OBSOLETE20;
enum CURLE_LIBRARY_NOT_FOUND = CURLcode.CURLE_OBSOLETE40;
enum CURLE_MALFORMAT_USER = CURLcode.CURLE_OBSOLETE24;
enum CURLE_SHARE_IN_USE = CURLcode.CURLE_OBSOLETE57;
enum CURLE_URL_MALFORMAT_USER = CURLcode.CURLE_NOT_BUILT_IN;

enum CURLE_FTP_ACCESS_DENIED = CURLcode.CURLE_REMOTE_ACCESS_DENIED;
enum CURLE_FTP_COULDNT_SET_BINARY = CURLcode.CURLE_FTP_COULDNT_SET_TYPE;
enum CURLE_FTP_QUOTE_ERROR = CURLcode.CURLE_QUOTE_ERROR;
enum CURLE_TFTP_DISKFULL = CURLcode.CURLE_REMOTE_DISK_FULL;
enum CURLE_TFTP_EXISTS = CURLcode.CURLE_REMOTE_FILE_EXISTS;
enum CURLE_HTTP_RANGE_ERROR = CURLcode.CURLE_RANGE_ERROR;
enum CURLE_FTP_SSL_FAILED = CURLcode.CURLE_USE_SSL_FAILED;

/* The following were added earlier */

enum CURLE_OPERATION_TIMEOUTED = CURLcode.CURLE_OPERATION_TIMEDOUT;
enum CURLE_HTTP_NOT_FOUND = CURLcode.CURLE_HTTP_RETURNED_ERROR;
enum CURLE_HTTP_PORT_FAILED = CURLcode.CURLE_INTERFACE_FAILED;
enum CURLE_FTP_COULDNT_STOR_FILE = CURLcode.CURLE_UPLOAD_FAILED;
enum CURLE_FTP_PARTIAL_FILE = CURLcode.CURLE_PARTIAL_FILE;
enum CURLE_FTP_BAD_DOWNLOAD_RESUME = CURLcode.CURLE_BAD_DOWNLOAD_RESUME;
enum CURLE_LDAP_INVALID_URL = CURLcode.CURLE_OBSOLETE62;
enum CURLE_CONV_REQD = CURLcode.CURLE_OBSOLETE76;
enum CURLE_CONV_FAILED = CURLcode.CURLE_OBSOLETE75;

/* This was the error code 50 in 7.7.3 and a few earlier versions, this
   is no longer used by libcurl but is instead #defined here only to not
   make programs break */
enum CURLE_ALREADY_COMPLETE = 99999;

/* Provide defines for really old option names */
enum CURLOPT_FILE = CURLoption.CURLOPT_WRITEDATA; /* name changed in 7.9.7 */
enum CURLOPT_INFILE = CURLoption.CURLOPT_READDATA; /* name changed in 7.9.7 */
enum CURLOPT_WRITEHEADER = CURLoption.CURLOPT_HEADERDATA;

/* Since long deprecated options with no code in the lib that does anything
   with them. */
enum CURLOPT_WRITEINFO = CURLoption.CURLOPT_OBSOLETE40;
enum CURLOPT_CLOSEPOLICY = CURLoption.CURLOPT_OBSOLETE72;

/* !CURL_NO_OLDIES */

/*
 * Proxy error codes. Returned in CURLINFO_PROXY_ERROR if CURLE_PROXY was
 * return for the transfers.
 */
enum CURLproxycode
{
    CURLPX_OK = 0,
    CURLPX_BAD_ADDRESS_TYPE = 1,
    CURLPX_BAD_VERSION = 2,
    CURLPX_CLOSED = 3,
    CURLPX_GSSAPI = 4,
    CURLPX_GSSAPI_PERMSG = 5,
    CURLPX_GSSAPI_PROTECTION = 6,
    CURLPX_IDENTD = 7,
    CURLPX_IDENTD_DIFFER = 8,
    CURLPX_LONG_HOSTNAME = 9,
    CURLPX_LONG_PASSWD = 10,
    CURLPX_LONG_USER = 11,
    CURLPX_NO_AUTH = 12,
    CURLPX_RECV_ADDRESS = 13,
    CURLPX_RECV_AUTH = 14,
    CURLPX_RECV_CONNECT = 15,
    CURLPX_RECV_REQACK = 16,
    CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 17,
    CURLPX_REPLY_COMMAND_NOT_SUPPORTED = 18,
    CURLPX_REPLY_CONNECTION_REFUSED = 19,
    CURLPX_REPLY_GENERAL_SERVER_FAILURE = 20,
    CURLPX_REPLY_HOST_UNREACHABLE = 21,
    CURLPX_REPLY_NETWORK_UNREACHABLE = 22,
    CURLPX_REPLY_NOT_ALLOWED = 23,
    CURLPX_REPLY_TTL_EXPIRED = 24,
    CURLPX_REPLY_UNASSIGNED = 25,
    CURLPX_REQUEST_FAILED = 26,
    CURLPX_RESOLVE_HOST = 27,
    CURLPX_SEND_AUTH = 28,
    CURLPX_SEND_CONNECT = 29,
    CURLPX_SEND_REQUEST = 30,
    CURLPX_UNKNOWN_FAIL = 31,
    CURLPX_UNKNOWN_MODE = 32,
    CURLPX_USER_REJECTED = 33,
    CURLPX_LAST /* never use */
}

/* This prototype applies to all conversion callbacks */
alias curl_conv_callback = CURLcode function (char* buffer, size_t length);

alias curl_ssl_ctx_callback = CURLcode function (
    CURL* curl, /* easy handle */
    void* ssl_ctx, /* actually an OpenSSL
                      or WolfSSL SSL_CTX,
                      or an mbedTLS
                    mbedtls_ssl_config */
    void* userptr);

enum curl_proxytype
{
    CURLPROXY_HTTP = 0, /* added in 7.10, new in 7.19.4 default is to use
       CONNECT HTTP/1.1 */
    CURLPROXY_HTTP_1_0 = 1, /* added in 7.19.4, force to use CONNECT
       HTTP/1.0  */
    CURLPROXY_HTTPS = 2, /* HTTPS but stick to HTTP/1 added in 7.52.0 */
    CURLPROXY_HTTPS2 = 3, /* HTTPS and attempt HTTP/2 added in 8.2.0 */
    CURLPROXY_SOCKS4 = 4, /* support added in 7.15.2, enum existed already
       in 7.10 */
    CURLPROXY_SOCKS5 = 5, /* added in 7.10 */
    CURLPROXY_SOCKS4A = 6, /* added in 7.18.0 */
    CURLPROXY_SOCKS5_HOSTNAME = 7 /* Use the SOCKS5 protocol but pass along the
       host name rather than the IP address. added
       in 7.18.0 */
} /* this enum was added in 7.10 */

/*
 * Bitmasks for CURLOPT_HTTPAUTH and CURLOPT_PROXYAUTH options:
 *
 * CURLAUTH_NONE         - No HTTP authentication
 * CURLAUTH_BASIC        - HTTP Basic authentication (default)
 * CURLAUTH_DIGEST       - HTTP Digest authentication
 * CURLAUTH_NEGOTIATE    - HTTP Negotiate (SPNEGO) authentication
 * CURLAUTH_GSSNEGOTIATE - Alias for CURLAUTH_NEGOTIATE (deprecated)
 * CURLAUTH_NTLM         - HTTP NTLM authentication
 * CURLAUTH_DIGEST_IE    - HTTP Digest authentication with IE flavour
 * CURLAUTH_NTLM_WB      - HTTP NTLM authentication delegated to winbind helper
 * CURLAUTH_BEARER       - HTTP Bearer token authentication
 * CURLAUTH_ONLY         - Use together with a single other type to force no
 *                         authentication or just that single type
 * CURLAUTH_ANY          - All fine types set
 * CURLAUTH_ANYSAFE      - All fine types except Basic
 */

enum CURLAUTH_NONE = cast(c_ulong) 0;
enum CURLAUTH_BASIC = (cast(c_ulong) 1) << 0;
enum CURLAUTH_DIGEST = (cast(c_ulong) 1) << 1;
enum CURLAUTH_NEGOTIATE = (cast(c_ulong) 1) << 2;
/* Deprecated since the advent of CURLAUTH_NEGOTIATE */
enum CURLAUTH_GSSNEGOTIATE = CURLAUTH_NEGOTIATE;
/* Used for CURLOPT_SOCKS5_AUTH to stay terminologically correct */
enum CURLAUTH_GSSAPI = CURLAUTH_NEGOTIATE;
enum CURLAUTH_NTLM = (cast(c_ulong) 1) << 3;
enum CURLAUTH_DIGEST_IE = (cast(c_ulong) 1) << 4;
enum CURLAUTH_NTLM_WB = (cast(c_ulong) 1) << 5;
enum CURLAUTH_BEARER = (cast(c_ulong) 1) << 6;
enum CURLAUTH_AWS_SIGV4 = (cast(c_ulong) 1) << 7;
enum CURLAUTH_ONLY = (cast(c_ulong) 1) << 31;
enum CURLAUTH_ANY = ~CURLAUTH_DIGEST_IE;
enum CURLAUTH_ANYSAFE = ~(CURLAUTH_BASIC | CURLAUTH_DIGEST_IE);

enum CURLSSH_AUTH_ANY = ~0; /* all types supported by the server */
enum CURLSSH_AUTH_NONE = 0; /* none allowed, silly but complete */
enum CURLSSH_AUTH_PUBLICKEY = 1 << 0; /* public/private key files */
enum CURLSSH_AUTH_PASSWORD = 1 << 1; /* password */
enum CURLSSH_AUTH_HOST = 1 << 2; /* host key files */
enum CURLSSH_AUTH_KEYBOARD = 1 << 3; /* keyboard interactive */
enum CURLSSH_AUTH_AGENT = 1 << 4; /* agent (ssh-agent, pageant...) */
enum CURLSSH_AUTH_GSSAPI = 1 << 5; /* gssapi (kerberos, ...) */
enum CURLSSH_AUTH_DEFAULT = CURLSSH_AUTH_ANY;

enum CURLGSSAPI_DELEGATION_NONE = 0; /* no delegation (default) */
enum CURLGSSAPI_DELEGATION_POLICY_FLAG = 1 << 0; /* if permitted by policy */
enum CURLGSSAPI_DELEGATION_FLAG = 1 << 1; /* delegate always */

enum CURL_ERROR_SIZE = 256;

enum curl_khtype
{
    CURLKHTYPE_UNKNOWN = 0,
    CURLKHTYPE_RSA1 = 1,
    CURLKHTYPE_RSA = 2,
    CURLKHTYPE_DSS = 3,
    CURLKHTYPE_ECDSA = 4,
    CURLKHTYPE_ED25519 = 5
}

struct curl_khkey
{
    const(char)* key; /* points to a null-terminated string encoded with base64
       if len is zero, otherwise to the "raw" data */
    size_t len;
    curl_khtype keytype;
}

/* this is the set of return values expected from the curl_sshkeycallback
   callback */
enum curl_khstat
{
    CURLKHSTAT_FINE_ADD_TO_FILE = 0,
    CURLKHSTAT_FINE = 1,
    CURLKHSTAT_REJECT = 2, /* reject the connection, return an error */
    CURLKHSTAT_DEFER = 3, /* do not accept it, but we can't answer right now.
       Causes a CURLE_PEER_FAILED_VERIFICATION error but the
       connection will be left intact etc */
    CURLKHSTAT_FINE_REPLACE = 4, /* accept and replace the wrong key */
    CURLKHSTAT_LAST /* not for use, only a marker for last-in-list */
}

/* this is the set of status codes pass in to the callback */
enum curl_khmatch
{
    CURLKHMATCH_OK = 0, /* match */
    CURLKHMATCH_MISMATCH = 1, /* host found, key mismatch! */
    CURLKHMATCH_MISSING = 2, /* no matching host/key found */
    CURLKHMATCH_LAST /* not for use, only a marker for last-in-list */
}

alias curl_sshkeycallback = int function (
    CURL* easy,                  /* easy handle */
    const(curl_khkey)* knownkey, /* known */
    const(curl_khkey)* foundkey, /* found */
    curl_khmatch,                /* libcurl's view on the keys */
    void* clientp);              /* custom pointer passed with */
                                 /* CURLOPT_SSH_KEYDATA */

alias curl_sshhostkeycallback = int function (
    void* clientp,    /* custom pointer passed */
                      /* with CURLOPT_SSH_HOSTKEYDATA */
    int keytype,      /* CURLKHTYPE */
    const(char)* key, /* hostkey to check */
    size_t keylen);   /* length of the key */
/* return CURLE_OK to accept */
/* or something else to refuse */

/* parameter for the CURLOPT_USE_SSL option */
enum curl_usessl
{
    CURLUSESSL_NONE = 0, /* do not attempt to use SSL */
    CURLUSESSL_TRY = 1, /* try using SSL, proceed anyway otherwise */
    CURLUSESSL_CONTROL = 2, /* SSL for the control connection or fail */
    CURLUSESSL_ALL = 3, /* SSL for all communication or fail */
    CURLUSESSL_LAST /* not an option, never use */
}

/* Definition of bits for the CURLOPT_SSL_OPTIONS argument: */

/* - ALLOW_BEAST tells libcurl to allow the BEAST SSL vulnerability in the
   name of improving interoperability with older servers. Some SSL libraries
   have introduced work-arounds for this flaw but those work-arounds sometimes
   make the SSL communication fail. To regain functionality with those broken
   servers, a user can this way allow the vulnerability back. */
enum CURLSSLOPT_ALLOW_BEAST = 1 << 0;

/* - NO_REVOKE tells libcurl to disable certificate revocation checks for those
   SSL backends where such behavior is present. */
enum CURLSSLOPT_NO_REVOKE = 1 << 1;

/* - NO_PARTIALCHAIN tells libcurl to *NOT* accept a partial certificate chain
   if possible. The OpenSSL backend has this ability. */
enum CURLSSLOPT_NO_PARTIALCHAIN = 1 << 2;

/* - REVOKE_BEST_EFFORT tells libcurl to ignore certificate revocation offline
   checks and ignore missing revocation list for those SSL backends where such
   behavior is present. */
enum CURLSSLOPT_REVOKE_BEST_EFFORT = 1 << 3;

/* - CURLSSLOPT_NATIVE_CA tells libcurl to use standard certificate store of
   operating system. Currently implemented under MS-Windows. */
enum CURLSSLOPT_NATIVE_CA = 1 << 4;

/* - CURLSSLOPT_AUTO_CLIENT_CERT tells libcurl to automatically locate and use
   a client certificate for authentication. (Schannel) */
enum CURLSSLOPT_AUTO_CLIENT_CERT = 1 << 5;

/* The default connection attempt delay in milliseconds for happy eyeballs.
   CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS.3 and happy-eyeballs-timeout-ms.d document
   this value, keep them in sync. */
enum CURL_HET_DEFAULT = 200L;

/* The default connection upkeep interval in milliseconds. */
enum CURL_UPKEEP_INTERVAL_DEFAULT = 60000L;

/* define CURL_NO_OLDIES to test if your app builds with all
   the obsolete stuff removed! */

/* Backwards compatibility with older names */
/* These are scheduled to disappear by 2009 */

enum CURLFTPSSL_NONE = curl_usessl.CURLUSESSL_NONE;
enum CURLFTPSSL_TRY = curl_usessl.CURLUSESSL_TRY;
enum CURLFTPSSL_CONTROL = curl_usessl.CURLUSESSL_CONTROL;
enum CURLFTPSSL_ALL = curl_usessl.CURLUSESSL_ALL;
enum CURLFTPSSL_LAST = curl_usessl.CURLUSESSL_LAST;
alias curl_ftpssl = curl_usessl;
/* !CURL_NO_OLDIES */

/* parameter for the CURLOPT_FTP_SSL_CCC option */
enum curl_ftpccc
{
    CURLFTPSSL_CCC_NONE = 0, /* do not send CCC */
    CURLFTPSSL_CCC_PASSIVE = 1, /* Let the server initiate the shutdown */
    CURLFTPSSL_CCC_ACTIVE = 2, /* Initiate the shutdown */
    CURLFTPSSL_CCC_LAST /* not an option, never use */
}

/* parameter for the CURLOPT_FTPSSLAUTH option */
enum curl_ftpauth
{
    CURLFTPAUTH_DEFAULT = 0, /* let libcurl decide */
    CURLFTPAUTH_SSL = 1, /* use "AUTH SSL" */
    CURLFTPAUTH_TLS = 2, /* use "AUTH TLS" */
    CURLFTPAUTH_LAST /* not an option, never use */
}

/* parameter for the CURLOPT_FTP_CREATE_MISSING_DIRS option */
enum curl_ftpcreatedir
{
    CURLFTP_CREATE_DIR_NONE = 0, /* do NOT create missing dirs! */
    CURLFTP_CREATE_DIR = 1, /* (FTP/SFTP) if CWD fails, try MKD and then CWD
       again if MKD succeeded, for SFTP this does
       similar magic */
    CURLFTP_CREATE_DIR_RETRY = 2, /* (FTP only) if CWD fails, try MKD and then CWD
       again even if MKD failed! */
    CURLFTP_CREATE_DIR_LAST /* not an option, never use */
}

/* parameter for the CURLOPT_FTP_FILEMETHOD option */
enum curl_ftpmethod
{
    CURLFTPMETHOD_DEFAULT = 0, /* let libcurl pick */
    CURLFTPMETHOD_MULTICWD = 1, /* single CWD operation for each path part */
    CURLFTPMETHOD_NOCWD = 2, /* no CWD at all */
    CURLFTPMETHOD_SINGLECWD = 3, /* one CWD to full dir, then work on file */
    CURLFTPMETHOD_LAST /* not an option, never use */
}

/* bitmask defines for CURLOPT_HEADEROPT */
enum CURLHEADER_UNIFIED = 0;
enum CURLHEADER_SEPARATE = 1 << 0;

/* CURLALTSVC_* are bits for the CURLOPT_ALTSVC_CTRL option */
enum CURLALTSVC_READONLYFILE = 1 << 2;
enum CURLALTSVC_H1 = 1 << 3;
enum CURLALTSVC_H2 = 1 << 4;
enum CURLALTSVC_H3 = 1 << 5;

struct curl_hstsentry
{
    import std.bitmanip : bitfields;

    char* name;
    size_t namelen;

    mixin(bitfields!(
        uint, "includeSubDomains", 1,
        uint, "", 7));

    char[18] expire; /* YYYYMMDD HH:MM:SS [null-terminated] */
}

struct curl_index
{
    size_t index; /* the provided entry's "index" or count */
    size_t total; /* total number of entries to save */
}

enum CURLSTScode
{
    CURLSTS_OK = 0,
    CURLSTS_DONE = 1,
    CURLSTS_FAIL = 2
}

alias curl_hstsread_callback = CURLSTScode function (
    CURL* easy,
    curl_hstsentry* e,
    void* userp);
alias curl_hstswrite_callback = CURLSTScode function (
    CURL* easy,
    curl_hstsentry* e,
    curl_index* i,
    void* userp);

/* CURLHSTS_* are bits for the CURLOPT_HSTS option */
enum CURLHSTS_ENABLE = cast(c_long) 1 << 0;
enum CURLHSTS_READONLYFILE = cast(c_long) 1 << 1;

/* The CURLPROTO_ defines below are for the **deprecated** CURLOPT_*PROTOCOLS
   options. Do not use. */
enum CURLPROTO_HTTP = 1 << 0;
enum CURLPROTO_HTTPS = 1 << 1;
enum CURLPROTO_FTP = 1 << 2;
enum CURLPROTO_FTPS = 1 << 3;
enum CURLPROTO_SCP = 1 << 4;
enum CURLPROTO_SFTP = 1 << 5;
enum CURLPROTO_TELNET = 1 << 6;
enum CURLPROTO_LDAP = 1 << 7;
enum CURLPROTO_LDAPS = 1 << 8;
enum CURLPROTO_DICT = 1 << 9;
enum CURLPROTO_FILE = 1 << 10;
enum CURLPROTO_TFTP = 1 << 11;
enum CURLPROTO_IMAP = 1 << 12;
enum CURLPROTO_IMAPS = 1 << 13;
enum CURLPROTO_POP3 = 1 << 14;
enum CURLPROTO_POP3S = 1 << 15;
enum CURLPROTO_SMTP = 1 << 16;
enum CURLPROTO_SMTPS = 1 << 17;
enum CURLPROTO_RTSP = 1 << 18;
enum CURLPROTO_RTMP = 1 << 19;
enum CURLPROTO_RTMPT = 1 << 20;
enum CURLPROTO_RTMPE = 1 << 21;
enum CURLPROTO_RTMPTE = 1 << 22;
enum CURLPROTO_RTMPS = 1 << 23;
enum CURLPROTO_RTMPTS = 1 << 24;
enum CURLPROTO_GOPHER = 1 << 25;
enum CURLPROTO_SMB = 1 << 26;
enum CURLPROTO_SMBS = 1 << 27;
enum CURLPROTO_MQTT = 1 << 28;
enum CURLPROTO_GOPHERS = 1 << 29;
enum CURLPROTO_ALL = ~0; /* enable everything */

/* long may be 32 or 64 bits, but we should never depend on anything else
   but 32 */
enum CURLOPTTYPE_LONG = 0;
enum CURLOPTTYPE_OBJECTPOINT = 10000;
enum CURLOPTTYPE_FUNCTIONPOINT = 20000;
enum CURLOPTTYPE_OFF_T = 30000;
enum CURLOPTTYPE_BLOB = 40000;

/* *STRINGPOINT is an alias for OBJECTPOINT to allow tools to extract the
   string options from the header file */

/* CURLOPT aliases that make no run-time difference */

/* 'char *' argument to a string with a trailing zero */
enum CURLOPTTYPE_STRINGPOINT = CURLOPTTYPE_OBJECTPOINT;

/* 'struct curl_slist *' argument */
enum CURLOPTTYPE_SLISTPOINT = CURLOPTTYPE_OBJECTPOINT;

/* 'void *' argument passed untouched to callback */
enum CURLOPTTYPE_CBPOINT = CURLOPTTYPE_OBJECTPOINT;

/* 'long' argument with a set of values/bitmask */
enum CURLOPTTYPE_VALUES = CURLOPTTYPE_LONG;

/*
 * All CURLOPT_* values.
 */

enum CURLoption
{
    /* This is the FILE * or void * the regular output should be written to. */
    CURLOPT_WRITEDATA = 10001,

    /* The full URL to get/put */
    CURLOPT_URL = 10002,

    /* Port number to connect to, if other than default. */
    CURLOPT_PORT = 3,

    /* Name of proxy to use. */
    CURLOPT_PROXY = 10004,

    /* "user:password;options" to use when fetching. */
    CURLOPT_USERPWD = 10005,

    /* "user:password" to use with proxy. */
    CURLOPT_PROXYUSERPWD = 10006,

    /* Range to get, specified as an ASCII string. */
    CURLOPT_RANGE = 10007,

    /* not used */

    /* Specified file stream to upload from (use as input): */
    CURLOPT_READDATA = 10009,

    /* Buffer to receive error messages in, must be at least CURL_ERROR_SIZE
     * bytes big. */
    CURLOPT_ERRORBUFFER = 10010,

    /* Function that will be called to store the output (instead of fwrite). The
     * parameters will use fwrite() syntax, make sure to follow them. */
    CURLOPT_WRITEFUNCTION = 20011,

    /* Function that will be called to read the input (instead of fread). The
     * parameters will use fread() syntax, make sure to follow them. */
    CURLOPT_READFUNCTION = 20012,

    /* Time-out the read operation after this amount of seconds */
    CURLOPT_TIMEOUT = 13,

    /* If CURLOPT_READDATA is used, this can be used to inform libcurl about
     * how large the file being sent really is. That allows better error
     * checking and better verifies that the upload was successful. -1 means
     * unknown size.
     *
     * For large file support, there is also a _LARGE version of the key
     * which takes an off_t type, allowing platforms with larger off_t
     * sizes to handle larger files.  See below for INFILESIZE_LARGE.
     */
    CURLOPT_INFILESIZE = 14,

    /* POST static input fields. */
    CURLOPT_POSTFIELDS = 10015,

    /* Set the referrer page (needed by some CGIs) */
    CURLOPT_REFERER = 10016,

    /* Set the FTP PORT string (interface name, named or numerical IP address)
       Use i.e '-' to use default address. */
    CURLOPT_FTPPORT = 10017,

    /* Set the User-Agent string (examined by some CGIs) */
    CURLOPT_USERAGENT = 10018,

    /* If the download receives less than "low speed limit" bytes/second
     * during "low speed time" seconds, the operations is aborted.
     * You could i.e if you have a pretty high speed connection, abort if
     * it is less than 2000 bytes/sec during 20 seconds.
     */

    /* Set the "low speed limit" */
    CURLOPT_LOW_SPEED_LIMIT = 19,

    /* Set the "low speed time" */
    CURLOPT_LOW_SPEED_TIME = 20,

    /* Set the continuation offset.
     *
     * Note there is also a _LARGE version of this key which uses
     * off_t types, allowing for large file offsets on platforms which
     * use larger-than-32-bit off_t's.  Look below for RESUME_FROM_LARGE.
     */
    CURLOPT_RESUME_FROM = 21,

    /* Set cookie in request: */
    CURLOPT_COOKIE = 10022,

    /* This points to a linked list of headers, struct curl_slist kind. This
       list is also used for RTSP (in spite of its name) */
    CURLOPT_HTTPHEADER = 10023,

    /* This points to a linked list of post entries, struct curl_httppost */
    CURLOPT_HTTPPOST = 10024,

    /* name of the file keeping your private SSL-certificate */
    CURLOPT_SSLCERT = 10025,

    /* password for the SSL or SSH private key */
    CURLOPT_KEYPASSWD = 10026,

    /* send TYPE parameter? */
    CURLOPT_CRLF = 27,

    /* send linked-list of QUOTE commands */
    CURLOPT_QUOTE = 10028,

    /* send FILE * or void * to store headers to, if you use a callback it
       is simply passed to the callback unmodified */
    CURLOPT_HEADERDATA = 10029,

    /* point to a file to read the initial cookies from, also enables
       "cookie awareness" */
    CURLOPT_COOKIEFILE = 10031,

    /* What version to specifically try to use.
       See CURL_SSLVERSION defines below. */
    CURLOPT_SSLVERSION = 32,

    /* What kind of HTTP time condition to use, see defines */
    CURLOPT_TIMECONDITION = 33,

    /* Time to use with the above condition. Specified in number of seconds
       since 1 Jan 1970 */
    CURLOPT_TIMEVALUE = 34,

    /* 35 = OBSOLETE */

    /* Custom request, for customizing the get command like
       HTTP: DELETE, TRACE and others
       FTP: to use a different list command
       */
    CURLOPT_CUSTOMREQUEST = 10036,

    /* FILE handle to use instead of stderr */
    CURLOPT_STDERR = 10037,

    /* 38 is not used */

    /* send linked-list of post-transfer QUOTE commands */
    CURLOPT_POSTQUOTE = 10039,

    /* OBSOLETE, do not use! */
    CURLOPT_OBSOLETE40 = 10040,

    /* talk a lot */
    CURLOPT_VERBOSE = 41,

    /* throw the header out too */
    CURLOPT_HEADER = 42,

    /* shut off the progress meter */
    CURLOPT_NOPROGRESS = 43,

    /* use HEAD to get http document */
    CURLOPT_NOBODY = 44,

    /* no output on http error codes >= 400 */
    CURLOPT_FAILONERROR = 45,

    /* this is an upload */
    CURLOPT_UPLOAD = 46,

    /* HTTP POST method */
    CURLOPT_POST = 47,

    /* bare names when listing directories */
    CURLOPT_DIRLISTONLY = 48,

    /* Append instead of overwrite on upload! */
    CURLOPT_APPEND = 50,

    /* Specify whether to read the user+password from the .netrc or the URL.
     * This must be one of the CURL_NETRC_* enums below. */
    CURLOPT_NETRC = 51,

    /* use Location: Luke! */
    CURLOPT_FOLLOWLOCATION = 52,

    /* transfer data in text/ASCII format */
    CURLOPT_TRANSFERTEXT = 53,

    /* HTTP PUT */
    CURLOPT_PUT = 54,

    /* 55 = OBSOLETE */

    /* DEPRECATED
     * Function that will be called instead of the internal progress display
     * function. This function should be defined as the curl_progress_callback
     * prototype defines. */
    CURLOPT_PROGRESSFUNCTION = 20056,

    /* Data passed to the CURLOPT_PROGRESSFUNCTION and CURLOPT_XFERINFOFUNCTION
       callbacks */
    CURLOPT_XFERINFODATA = 10057,

    /* We want the referrer field set automatically when following locations */
    CURLOPT_AUTOREFERER = 58,

    /* Port of the proxy, can be set in the proxy string as well with:
       "[host]:[port]" */
    CURLOPT_PROXYPORT = 59,

    /* size of the POST input data, if strlen() is not good to use */
    CURLOPT_POSTFIELDSIZE = 60,

    /* tunnel non-http operations through an HTTP proxy */
    CURLOPT_HTTPPROXYTUNNEL = 61,

    /* Set the interface string to use as outgoing network interface */
    CURLOPT_INTERFACE = 10062,

    /* Set the krb4/5 security level, this also enables krb4/5 awareness.  This
     * is a string, 'clear', 'safe', 'confidential' or 'private'.  If the string
     * is set but doesn't match one of these, 'private' will be used.  */
    CURLOPT_KRBLEVEL = 10063,

    /* Set if we should verify the peer in ssl handshake, set 1 to verify. */
    CURLOPT_SSL_VERIFYPEER = 64,

    /* The CApath or CAfile used to validate the peer certificate
       this option is used only if SSL_VERIFYPEER is true */
    CURLOPT_CAINFO = 10065,

    /* 66 = OBSOLETE */
    /* 67 = OBSOLETE */

    /* Maximum number of http redirects to follow */
    CURLOPT_MAXREDIRS = 68,

    /* Pass a long set to 1 to get the date of the requested document (if
       possible)! Pass a zero to shut it off. */
    CURLOPT_FILETIME = 69,

    /* This points to a linked list of telnet options */
    CURLOPT_TELNETOPTIONS = 10070,

    /* Max amount of cached alive connections */
    CURLOPT_MAXCONNECTS = 71,

    /* OBSOLETE, do not use! */
    CURLOPT_OBSOLETE72 = 72,

    /* 73 = OBSOLETE */

    /* Set to explicitly use a new connection for the upcoming transfer.
       Do not use this unless you're absolutely sure of this, as it makes the
       operation slower and is less friendly for the network. */
    CURLOPT_FRESH_CONNECT = 74,

    /* Set to explicitly forbid the upcoming transfer's connection to be reused
       when done. Do not use this unless you're absolutely sure of this, as it
       makes the operation slower and is less friendly for the network. */
    CURLOPT_FORBID_REUSE = 75,

    /* Set to a file name that contains random data for libcurl to use to
       seed the random engine when doing SSL connects. */
    CURLOPT_RANDOM_FILE = 10076,

    /* Set to the Entropy Gathering Daemon socket pathname */
    CURLOPT_EGDSOCKET = 10077,

    /* Time-out connect operations after this amount of seconds, if connects are
       OK within this time, then fine... This only aborts the connect phase. */
    CURLOPT_CONNECTTIMEOUT = 78,

    /* Function that will be called to store headers (instead of fwrite). The
     * parameters will use fwrite() syntax, make sure to follow them. */
    CURLOPT_HEADERFUNCTION = 20079,

    /* Set this to force the HTTP request to get back to GET. Only really usable
       if POST, PUT or a custom request have been used first.
     */
    CURLOPT_HTTPGET = 80,

    /* Set if we should verify the Common name from the peer certificate in ssl
     * handshake, set 1 to check existence, 2 to ensure that it matches the
     * provided hostname. */
    CURLOPT_SSL_VERIFYHOST = 81,

    /* Specify which file name to write all known cookies in after completed
       operation. Set file name to "-" (dash) to make it go to stdout. */
    CURLOPT_COOKIEJAR = 10082,

    /* Specify which SSL ciphers to use */
    CURLOPT_SSL_CIPHER_LIST = 10083,

    /* Specify which HTTP version to use! This must be set to one of the
       CURL_HTTP_VERSION* enums set below. */
    CURLOPT_HTTP_VERSION = 84,

    /* Specifically switch on or off the FTP engine's use of the EPSV command. By
       default, that one will always be attempted before the more traditional
       PASV command. */
    CURLOPT_FTP_USE_EPSV = 85,

    /* type of the file keeping your SSL-certificate ("DER", "PEM", "ENG") */
    CURLOPT_SSLCERTTYPE = 10086,

    /* name of the file keeping your private SSL-key */
    CURLOPT_SSLKEY = 10087,

    /* type of the file keeping your private SSL-key ("DER", "PEM", "ENG") */
    CURLOPT_SSLKEYTYPE = 10088,

    /* crypto engine for the SSL-sub system */
    CURLOPT_SSLENGINE = 10089,

    /* set the crypto engine for the SSL-sub system as default
       the param has no meaning...
     */
    CURLOPT_SSLENGINE_DEFAULT = 90,

    /* Non-zero value means to use the global dns cache */
    /* DEPRECATED, do not use! */
    CURLOPT_DNS_USE_GLOBAL_CACHE = 91,

    /* DNS cache timeout */
    CURLOPT_DNS_CACHE_TIMEOUT = 92,

    /* send linked-list of pre-transfer QUOTE commands */
    CURLOPT_PREQUOTE = 10093,

    /* set the debug function */
    CURLOPT_DEBUGFUNCTION = 20094,

    /* set the data for the debug function */
    CURLOPT_DEBUGDATA = 10095,

    /* mark this as start of a cookie session */
    CURLOPT_COOKIESESSION = 96,

    /* The CApath directory used to validate the peer certificate
       this option is used only if SSL_VERIFYPEER is true */
    CURLOPT_CAPATH = 10097,

    /* Instruct libcurl to use a smaller receive buffer */
    CURLOPT_BUFFERSIZE = 98,

    /* Instruct libcurl to not use any signal/alarm handlers, even when using
       timeouts. This option is useful for multi-threaded applications.
       See libcurl-the-guide for more background information. */
    CURLOPT_NOSIGNAL = 99,

    /* Provide a CURLShare for mutexing non-ts data */
    CURLOPT_SHARE = 10100,

    /* indicates type of proxy. accepted values are CURLPROXY_HTTP (default),
       CURLPROXY_HTTPS, CURLPROXY_SOCKS4, CURLPROXY_SOCKS4A and
       CURLPROXY_SOCKS5. */
    CURLOPT_PROXYTYPE = 101,

    /* Set the Accept-Encoding string. Use this to tell a server you would like
       the response to be compressed. Before 7.21.6, this was known as
       CURLOPT_ENCODING */
    CURLOPT_ACCEPT_ENCODING = 10102,

    /* Set pointer to private data */
    CURLOPT_PRIVATE = 10103,

    /* Set aliases for HTTP 200 in the HTTP Response header */
    CURLOPT_HTTP200ALIASES = 10104,

    /* Continue to send authentication (user+password) when following locations,
       even when hostname changed. This can potentially send off the name
       and password to whatever host the server decides. */
    CURLOPT_UNRESTRICTED_AUTH = 105,

    /* Specifically switch on or off the FTP engine's use of the EPRT command (
       it also disables the LPRT attempt). By default, those ones will always be
       attempted before the good old traditional PORT command. */
    CURLOPT_FTP_USE_EPRT = 106,

    /* Set this to a bitmask value to enable the particular authentications
       methods you like. Use this in combination with CURLOPT_USERPWD.
       Note that setting multiple bits may cause extra network round-trips. */
    CURLOPT_HTTPAUTH = 107,

    /* Set the ssl context callback function, currently only for OpenSSL or
       WolfSSL ssl_ctx, or mbedTLS mbedtls_ssl_config in the second argument.
       The function must match the curl_ssl_ctx_callback prototype. */
    CURLOPT_SSL_CTX_FUNCTION = 20108,

    /* Set the userdata for the ssl context callback function's third
       argument */
    CURLOPT_SSL_CTX_DATA = 10109,

    /* FTP Option that causes missing dirs to be created on the remote server.
       In 7.19.4 we introduced the convenience enums for this option using the
       CURLFTP_CREATE_DIR prefix.
    */
    CURLOPT_FTP_CREATE_MISSING_DIRS = 110,

    /* Set this to a bitmask value to enable the particular authentications
       methods you like. Use this in combination with CURLOPT_PROXYUSERPWD.
       Note that setting multiple bits may cause extra network round-trips. */
    CURLOPT_PROXYAUTH = 111,

    /* Option that changes the timeout, in seconds, associated with getting a
       response.  This is different from transfer timeout time and essentially
       places a demand on the server to acknowledge commands in a timely
       manner. For FTP, SMTP, IMAP and POP3. */
    CURLOPT_SERVER_RESPONSE_TIMEOUT = 112,

    /* Set this option to one of the CURL_IPRESOLVE_* defines (see below) to
       tell libcurl to use those IP versions only. This only has effect on
       systems with support for more than one, i.e IPv4 _and_ IPv6. */
    CURLOPT_IPRESOLVE = 113,

    /* Set this option to limit the size of a file that will be downloaded from
       an HTTP or FTP server.

       Note there is also _LARGE version which adds large file support for
       platforms which have larger off_t sizes.  See MAXFILESIZE_LARGE below. */
    CURLOPT_MAXFILESIZE = 114,

    /* See the comment for INFILESIZE above, but in short, specifies
     * the size of the file being uploaded.  -1 means unknown.
     */
    CURLOPT_INFILESIZE_LARGE = 30115,

    /* Sets the continuation offset.  There is also a CURLOPTTYPE_LONG version
     * of this; look above for RESUME_FROM.
     */
    CURLOPT_RESUME_FROM_LARGE = 30116,

    /* Sets the maximum size of data that will be downloaded from
     * an HTTP or FTP server.  See MAXFILESIZE above for the LONG version.
     */
    CURLOPT_MAXFILESIZE_LARGE = 30117,

    /* Set this option to the file name of your .netrc file you want libcurl
       to parse (using the CURLOPT_NETRC option). If not set, libcurl will do
       a poor attempt to find the user's home directory and check for a .netrc
       file in there. */
    CURLOPT_NETRC_FILE = 10118,

    /* Enable SSL/TLS for FTP, pick one of:
       CURLUSESSL_TRY     - try using SSL, proceed anyway otherwise
       CURLUSESSL_CONTROL - SSL for the control connection or fail
       CURLUSESSL_ALL     - SSL for all communication or fail
    */
    CURLOPT_USE_SSL = 119,

    /* The _LARGE version of the standard POSTFIELDSIZE option */
    CURLOPT_POSTFIELDSIZE_LARGE = 30120,

    /* Enable/disable the TCP Nagle algorithm */
    CURLOPT_TCP_NODELAY = 121,

    /* 122 OBSOLETE, used in 7.12.3. Gone in 7.13.0 */
    /* 123 OBSOLETE. Gone in 7.16.0 */
    /* 124 OBSOLETE, used in 7.12.3. Gone in 7.13.0 */
    /* 125 OBSOLETE, used in 7.12.3. Gone in 7.13.0 */
    /* 126 OBSOLETE, used in 7.12.3. Gone in 7.13.0 */
    /* 127 OBSOLETE. Gone in 7.16.0 */
    /* 128 OBSOLETE. Gone in 7.16.0 */

    /* When FTP over SSL/TLS is selected (with CURLOPT_USE_SSL), this option
       can be used to change libcurl's default action which is to first try
       "AUTH SSL" and then "AUTH TLS" in this order, and proceed when a OK
       response has been received.

       Available parameters are:
       CURLFTPAUTH_DEFAULT - let libcurl decide
       CURLFTPAUTH_SSL     - try "AUTH SSL" first, then TLS
       CURLFTPAUTH_TLS     - try "AUTH TLS" first, then SSL
    */
    CURLOPT_FTPSSLAUTH = 129,

    CURLOPT_IOCTLFUNCTION = 20130,

    CURLOPT_IOCTLDATA = 10131,

    /* 132 OBSOLETE. Gone in 7.16.0 */
    /* 133 OBSOLETE. Gone in 7.16.0 */

    /* null-terminated string for pass on to the FTP server when asked for
       "account" info */
    CURLOPT_FTP_ACCOUNT = 10134,

    /* feed cookie into cookie engine */
    CURLOPT_COOKIELIST = 10135,

    /* ignore Content-Length */
    CURLOPT_IGNORE_CONTENT_LENGTH = 136,

    /* Set to non-zero to skip the IP address received in a 227 PASV FTP server
       response. Typically used for FTP-SSL purposes but is not restricted to
       that. libcurl will then instead use the same IP address it used for the
       control connection. */
    CURLOPT_FTP_SKIP_PASV_IP = 137,

    /* Select "file method" to use when doing FTP, see the curl_ftpmethod
       above. */
    CURLOPT_FTP_FILEMETHOD = 138,

    /* Local port number to bind the socket to */
    CURLOPT_LOCALPORT = 139,

    /* Number of ports to try, including the first one set with LOCALPORT.
       Thus, setting it to 1 will make no additional attempts but the first.
    */
    CURLOPT_LOCALPORTRANGE = 140,

    /* no transfer, set up connection and let application use the socket by
       extracting it with CURLINFO_LASTSOCKET */
    CURLOPT_CONNECT_ONLY = 141,

    /* Function that will be called to convert from the
       network encoding (instead of using the iconv calls in libcurl) */
    CURLOPT_CONV_FROM_NETWORK_FUNCTION = 20142,

    /* Function that will be called to convert to the
       network encoding (instead of using the iconv calls in libcurl) */
    CURLOPT_CONV_TO_NETWORK_FUNCTION = 20143,

    /* Function that will be called to convert from UTF8
       (instead of using the iconv calls in libcurl)
       Note that this is used only for SSL certificate processing */
    CURLOPT_CONV_FROM_UTF8_FUNCTION = 20144,

    /* if the connection proceeds too quickly then need to slow it down */
    /* limit-rate: maximum number of bytes per second to send or receive */
    CURLOPT_MAX_SEND_SPEED_LARGE = 30145,
    CURLOPT_MAX_RECV_SPEED_LARGE = 30146,

    /* Pointer to command string to send if USER/PASS fails. */
    CURLOPT_FTP_ALTERNATIVE_TO_USER = 10147,

    /* callback function for setting socket options */
    CURLOPT_SOCKOPTFUNCTION = 20148,
    CURLOPT_SOCKOPTDATA = 10149,

    /* set to 0 to disable session ID reuse for this transfer, default is
       enabled (== 1) */
    CURLOPT_SSL_SESSIONID_CACHE = 150,

    /* allowed SSH authentication methods */
    CURLOPT_SSH_AUTH_TYPES = 151,

    /* Used by scp/sftp to do public/private key authentication */
    CURLOPT_SSH_PUBLIC_KEYFILE = 10152,
    CURLOPT_SSH_PRIVATE_KEYFILE = 10153,

    /* Send CCC (Clear Command Channel) after authentication */
    CURLOPT_FTP_SSL_CCC = 154,

    /* Same as TIMEOUT and CONNECTTIMEOUT, but with ms resolution */
    CURLOPT_TIMEOUT_MS = 155,
    CURLOPT_CONNECTTIMEOUT_MS = 156,

    /* set to zero to disable the libcurl's decoding and thus pass the raw body
       data to the application even when it is encoded/compressed */
    CURLOPT_HTTP_TRANSFER_DECODING = 157,
    CURLOPT_HTTP_CONTENT_DECODING = 158,

    /* Permission used when creating new files and directories on the remote
       server for protocols that support it, SFTP/SCP/FILE */
    CURLOPT_NEW_FILE_PERMS = 159,
    CURLOPT_NEW_DIRECTORY_PERMS = 160,

    /* Set the behavior of POST when redirecting. Values must be set to one
       of CURL_REDIR* defines below. This used to be called CURLOPT_POST301 */
    CURLOPT_POSTREDIR = 161,

    /* used by scp/sftp to verify the host's public key */
    CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 = 10162,

    /* Callback function for opening socket (instead of socket(2)). Optionally,
       callback is able change the address or refuse to connect returning
       CURL_SOCKET_BAD.  The callback should have type
       curl_opensocket_callback */
    CURLOPT_OPENSOCKETFUNCTION = 20163,
    CURLOPT_OPENSOCKETDATA = 10164,

    /* POST volatile input fields. */
    CURLOPT_COPYPOSTFIELDS = 10165,

    /* set transfer mode (;type=<a|i>) when doing FTP via an HTTP proxy */
    CURLOPT_PROXY_TRANSFER_MODE = 166,

    /* Callback function for seeking in the input stream */
    CURLOPT_SEEKFUNCTION = 20167,
    CURLOPT_SEEKDATA = 10168,

    /* CRL file */
    CURLOPT_CRLFILE = 10169,

    /* Issuer certificate */
    CURLOPT_ISSUERCERT = 10170,

    /* (IPv6) Address scope */
    CURLOPT_ADDRESS_SCOPE = 171,

    /* Collect certificate chain info and allow it to get retrievable with
       CURLINFO_CERTINFO after the transfer is complete. */
    CURLOPT_CERTINFO = 172,

    /* "name" and "pwd" to use when fetching. */
    CURLOPT_USERNAME = 10173,
    CURLOPT_PASSWORD = 10174,

    /* "name" and "pwd" to use with Proxy when fetching. */
    CURLOPT_PROXYUSERNAME = 10175,
    CURLOPT_PROXYPASSWORD = 10176,

    /* Comma separated list of hostnames defining no-proxy zones. These should
       match both hostnames directly, and hostnames within a domain. For
       example, local.com will match local.com and www.local.com, but NOT
       notlocal.com or www.notlocal.com. For compatibility with other
       implementations of this, .local.com will be considered to be the same as
       local.com. A single * is the only valid wildcard, and effectively
       disables the use of proxy. */
    CURLOPT_NOPROXY = 10177,

    /* block size for TFTP transfers */
    CURLOPT_TFTP_BLKSIZE = 178,

    /* Socks Service */
    /* DEPRECATED, do not use! */
    CURLOPT_SOCKS5_GSSAPI_SERVICE = 10179,

    /* Socks Service */
    CURLOPT_SOCKS5_GSSAPI_NEC = 180,

    /* set the bitmask for the protocols that are allowed to be used for the
       transfer, which thus helps the app which takes URLs from users or other
       external inputs and want to restrict what protocol(s) to deal
       with. Defaults to CURLPROTO_ALL. */
    CURLOPT_PROTOCOLS = 181,

    /* set the bitmask for the protocols that libcurl is allowed to follow to,
       as a subset of the CURLOPT_PROTOCOLS ones. That means the protocol needs
       to be set in both bitmasks to be allowed to get redirected to. */
    CURLOPT_REDIR_PROTOCOLS = 182,

    /* set the SSH knownhost file name to use */
    CURLOPT_SSH_KNOWNHOSTS = 10183,

    /* set the SSH host key callback, must point to a curl_sshkeycallback
       function */
    CURLOPT_SSH_KEYFUNCTION = 20184,

    /* set the SSH host key callback custom pointer */
    CURLOPT_SSH_KEYDATA = 10185,

    /* set the SMTP mail originator */
    CURLOPT_MAIL_FROM = 10186,

    /* set the list of SMTP mail receiver(s) */
    CURLOPT_MAIL_RCPT = 10187,

    /* FTP: send PRET before PASV */
    CURLOPT_FTP_USE_PRET = 188,

    /* RTSP request method (OPTIONS, SETUP, PLAY, etc...) */
    CURLOPT_RTSP_REQUEST = 189,

    /* The RTSP session identifier */
    CURLOPT_RTSP_SESSION_ID = 10190,

    /* The RTSP stream URI */
    CURLOPT_RTSP_STREAM_URI = 10191,

    /* The Transport: header to use in RTSP requests */
    CURLOPT_RTSP_TRANSPORT = 10192,

    /* Manually initialize the client RTSP CSeq for this handle */
    CURLOPT_RTSP_CLIENT_CSEQ = 193,

    /* Manually initialize the server RTSP CSeq for this handle */
    CURLOPT_RTSP_SERVER_CSEQ = 194,

    /* The stream to pass to INTERLEAVEFUNCTION. */
    CURLOPT_INTERLEAVEDATA = 10195,

    /* Let the application define a custom write method for RTP data */
    CURLOPT_INTERLEAVEFUNCTION = 20196,

    /* Turn on wildcard matching */
    CURLOPT_WILDCARDMATCH = 197,

    /* Directory matching callback called before downloading of an
       individual file (chunk) started */
    CURLOPT_CHUNK_BGN_FUNCTION = 20198,

    /* Directory matching callback called after the file (chunk)
       was downloaded, or skipped */
    CURLOPT_CHUNK_END_FUNCTION = 20199,

    /* Change match (fnmatch-like) callback for wildcard matching */
    CURLOPT_FNMATCH_FUNCTION = 20200,

    /* Let the application define custom chunk data pointer */
    CURLOPT_CHUNK_DATA = 10201,

    /* FNMATCH_FUNCTION user pointer */
    CURLOPT_FNMATCH_DATA = 10202,

    /* send linked-list of name:port:address sets */
    CURLOPT_RESOLVE = 10203,

    /* Set a username for authenticated TLS */
    CURLOPT_TLSAUTH_USERNAME = 10204,

    /* Set a password for authenticated TLS */
    CURLOPT_TLSAUTH_PASSWORD = 10205,

    /* Set authentication type for authenticated TLS */
    CURLOPT_TLSAUTH_TYPE = 10206,

    /* Set to 1 to enable the "TE:" header in HTTP requests to ask for
       compressed transfer-encoded responses. Set to 0 to disable the use of TE:
       in outgoing requests. The current default is 0, but it might change in a
       future libcurl release.

       libcurl will ask for the compressed methods it knows of, and if that
       isn't any, it will not ask for transfer-encoding at all even if this
       option is set to 1.

    */
    CURLOPT_TRANSFER_ENCODING = 207,

    /* Callback function for closing socket (instead of close(2)). The callback
       should have type curl_closesocket_callback */
    CURLOPT_CLOSESOCKETFUNCTION = 20208,
    CURLOPT_CLOSESOCKETDATA = 10209,

    /* allow GSSAPI credential delegation */
    CURLOPT_GSSAPI_DELEGATION = 210,

    /* Set the name servers to use for DNS resolution */
    CURLOPT_DNS_SERVERS = 10211,

    /* Time-out accept operations (currently for FTP only) after this amount
       of milliseconds. */
    CURLOPT_ACCEPTTIMEOUT_MS = 212,

    /* Set TCP keepalive */
    CURLOPT_TCP_KEEPALIVE = 213,

    /* non-universal keepalive knobs (Linux, AIX, HP-UX, more) */
    CURLOPT_TCP_KEEPIDLE = 214,
    CURLOPT_TCP_KEEPINTVL = 215,

    /* Enable/disable specific SSL features with a bitmask, see CURLSSLOPT_* */
    CURLOPT_SSL_OPTIONS = 216,

    /* Set the SMTP auth originator */
    CURLOPT_MAIL_AUTH = 10217,

    /* Enable/disable SASL initial response */
    CURLOPT_SASL_IR = 218,

    /* Function that will be called instead of the internal progress display
     * function. This function should be defined as the curl_xferinfo_callback
     * prototype defines. (Deprecates CURLOPT_PROGRESSFUNCTION) */
    CURLOPT_XFERINFOFUNCTION = 20219,

    /* The XOAUTH2 bearer token */
    CURLOPT_XOAUTH2_BEARER = 10220,

    /* Set the interface string to use as outgoing network
     * interface for DNS requests.
     * Only supported by the c-ares DNS backend */
    CURLOPT_DNS_INTERFACE = 10221,

    /* Set the local IPv4 address to use for outgoing DNS requests.
     * Only supported by the c-ares DNS backend */
    CURLOPT_DNS_LOCAL_IP4 = 10222,

    /* Set the local IPv6 address to use for outgoing DNS requests.
     * Only supported by the c-ares DNS backend */
    CURLOPT_DNS_LOCAL_IP6 = 10223,

    /* Set authentication options directly */
    CURLOPT_LOGIN_OPTIONS = 10224,

    /* Enable/disable TLS NPN extension (http2 over ssl might fail without) */
    CURLOPT_SSL_ENABLE_NPN = 225,

    /* Enable/disable TLS ALPN extension (http2 over ssl might fail without) */
    CURLOPT_SSL_ENABLE_ALPN = 226,

    /* Time to wait for a response to an HTTP request containing an
     * Expect: 100-continue header before sending the data anyway. */
    CURLOPT_EXPECT_100_TIMEOUT_MS = 227,

    /* This points to a linked list of headers used for proxy requests only,
       struct curl_slist kind */
    CURLOPT_PROXYHEADER = 10228,

    /* Pass in a bitmask of "header options" */
    CURLOPT_HEADEROPT = 229,

    /* The public key in DER form used to validate the peer public key
       this option is used only if SSL_VERIFYPEER is true */
    CURLOPT_PINNEDPUBLICKEY = 10230,

    /* Path to Unix domain socket */
    CURLOPT_UNIX_SOCKET_PATH = 10231,

    /* Set if we should verify the certificate status. */
    CURLOPT_SSL_VERIFYSTATUS = 232,

    /* Set if we should enable TLS false start. */
    CURLOPT_SSL_FALSESTART = 233,

    /* Do not squash dot-dot sequences */
    CURLOPT_PATH_AS_IS = 234,

    /* Proxy Service Name */
    CURLOPT_PROXY_SERVICE_NAME = 10235,

    /* Service Name */
    CURLOPT_SERVICE_NAME = 10236,

    /* Wait/don't wait for pipe/mutex to clarify */
    CURLOPT_PIPEWAIT = 237,

    /* Set the protocol used when curl is given a URL without a protocol */
    CURLOPT_DEFAULT_PROTOCOL = 10238,

    /* Set stream weight, 1 - 256 (default is 16) */
    CURLOPT_STREAM_WEIGHT = 239,

    /* Set stream dependency on another CURL handle */
    CURLOPT_STREAM_DEPENDS = 10240,

    /* Set E-xclusive stream dependency on another CURL handle */
    CURLOPT_STREAM_DEPENDS_E = 10241,

    /* Do not send any tftp option requests to the server */
    CURLOPT_TFTP_NO_OPTIONS = 242,

    /* Linked-list of host:port:connect-to-host:connect-to-port,
       overrides the URL's host:port (only for the network layer) */
    CURLOPT_CONNECT_TO = 10243,

    /* Set TCP Fast Open */
    CURLOPT_TCP_FASTOPEN = 244,

    /* Continue to send data if the server responds early with an
     * HTTP status code >= 300 */
    CURLOPT_KEEP_SENDING_ON_ERROR = 245,

    /* The CApath or CAfile used to validate the proxy certificate
       this option is used only if PROXY_SSL_VERIFYPEER is true */
    CURLOPT_PROXY_CAINFO = 10246,

    /* The CApath directory used to validate the proxy certificate
       this option is used only if PROXY_SSL_VERIFYPEER is true */
    CURLOPT_PROXY_CAPATH = 10247,

    /* Set if we should verify the proxy in ssl handshake,
       set 1 to verify. */
    CURLOPT_PROXY_SSL_VERIFYPEER = 248,

    /* Set if we should verify the Common name from the proxy certificate in ssl
     * handshake, set 1 to check existence, 2 to ensure that it matches
     * the provided hostname. */
    CURLOPT_PROXY_SSL_VERIFYHOST = 249,

    /* What version to specifically try to use for proxy.
       See CURL_SSLVERSION defines below. */
    CURLOPT_PROXY_SSLVERSION = 250,

    /* Set a username for authenticated TLS for proxy */
    CURLOPT_PROXY_TLSAUTH_USERNAME = 10251,

    /* Set a password for authenticated TLS for proxy */
    CURLOPT_PROXY_TLSAUTH_PASSWORD = 10252,

    /* Set authentication type for authenticated TLS for proxy */
    CURLOPT_PROXY_TLSAUTH_TYPE = 10253,

    /* name of the file keeping your private SSL-certificate for proxy */
    CURLOPT_PROXY_SSLCERT = 10254,

    /* type of the file keeping your SSL-certificate ("DER", "PEM", "ENG") for
       proxy */
    CURLOPT_PROXY_SSLCERTTYPE = 10255,

    /* name of the file keeping your private SSL-key for proxy */
    CURLOPT_PROXY_SSLKEY = 10256,

    /* type of the file keeping your private SSL-key ("DER", "PEM", "ENG") for
       proxy */
    CURLOPT_PROXY_SSLKEYTYPE = 10257,

    /* password for the SSL private key for proxy */
    CURLOPT_PROXY_KEYPASSWD = 10258,

    /* Specify which SSL ciphers to use for proxy */
    CURLOPT_PROXY_SSL_CIPHER_LIST = 10259,

    /* CRL file for proxy */
    CURLOPT_PROXY_CRLFILE = 10260,

    /* Enable/disable specific SSL features with a bitmask for proxy, see
       CURLSSLOPT_* */
    CURLOPT_PROXY_SSL_OPTIONS = 261,

    /* Name of pre proxy to use. */
    CURLOPT_PRE_PROXY = 10262,

    /* The public key in DER form used to validate the proxy public key
       this option is used only if PROXY_SSL_VERIFYPEER is true */
    CURLOPT_PROXY_PINNEDPUBLICKEY = 10263,

    /* Path to an abstract Unix domain socket */
    CURLOPT_ABSTRACT_UNIX_SOCKET = 10264,

    /* Suppress proxy CONNECT response headers from user callbacks */
    CURLOPT_SUPPRESS_CONNECT_HEADERS = 265,

    /* The request target, instead of extracted from the URL */
    CURLOPT_REQUEST_TARGET = 10266,

    /* bitmask of allowed auth methods for connections to SOCKS5 proxies */
    CURLOPT_SOCKS5_AUTH = 267,

    /* Enable/disable SSH compression */
    CURLOPT_SSH_COMPRESSION = 268,

    /* Post MIME data. */
    CURLOPT_MIMEPOST = 10269,

    /* Time to use with the CURLOPT_TIMECONDITION. Specified in number of
       seconds since 1 Jan 1970. */
    CURLOPT_TIMEVALUE_LARGE = 30270,

    /* Head start in milliseconds to give happy eyeballs. */
    CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS = 271,

    /* Function that will be called before a resolver request is made */
    CURLOPT_RESOLVER_START_FUNCTION = 20272,

    /* User data to pass to the resolver start callback. */
    CURLOPT_RESOLVER_START_DATA = 10273,

    /* send HAProxy PROXY protocol header? */
    CURLOPT_HAPROXYPROTOCOL = 274,

    /* shuffle addresses before use when DNS returns multiple */
    CURLOPT_DNS_SHUFFLE_ADDRESSES = 275,

    /* Specify which TLS 1.3 ciphers suites to use */
    CURLOPT_TLS13_CIPHERS = 10276,
    CURLOPT_PROXY_TLS13_CIPHERS = 10277,

    /* Disallow specifying username/login in URL. */
    CURLOPT_DISALLOW_USERNAME_IN_URL = 278,

    /* DNS-over-HTTPS URL */
    CURLOPT_DOH_URL = 10279,

    /* Preferred buffer size to use for uploads */
    CURLOPT_UPLOAD_BUFFERSIZE = 280,

    /* Time in ms between connection upkeep calls for long-lived connections. */
    CURLOPT_UPKEEP_INTERVAL_MS = 281,

    /* Specify URL using CURL URL API. */
    CURLOPT_CURLU = 10282,

    /* add trailing data just after no more data is available */
    CURLOPT_TRAILERFUNCTION = 20283,

    /* pointer to be passed to HTTP_TRAILER_FUNCTION */
    CURLOPT_TRAILERDATA = 10284,

    /* set this to 1L to allow HTTP/0.9 responses or 0L to disallow */
    CURLOPT_HTTP09_ALLOWED = 285,

    /* alt-svc control bitmask */
    CURLOPT_ALTSVC_CTRL = 286,

    /* alt-svc cache file name to possibly read from/write to */
    CURLOPT_ALTSVC = 10287,

    /* maximum age (idle time) of a connection to consider it for reuse
     * (in seconds) */
    CURLOPT_MAXAGE_CONN = 288,

    /* SASL authorization identity */
    CURLOPT_SASL_AUTHZID = 10289,

    /* allow RCPT TO command to fail for some recipients */
    CURLOPT_MAIL_RCPT_ALLOWFAILS = 290,

    /* the private SSL-certificate as a "blob" */
    CURLOPT_SSLCERT_BLOB = 40291,
    CURLOPT_SSLKEY_BLOB = 40292,
    CURLOPT_PROXY_SSLCERT_BLOB = 40293,
    CURLOPT_PROXY_SSLKEY_BLOB = 40294,
    CURLOPT_ISSUERCERT_BLOB = 40295,

    /* Issuer certificate for proxy */
    CURLOPT_PROXY_ISSUERCERT = 10296,
    CURLOPT_PROXY_ISSUERCERT_BLOB = 40297,

    /* the EC curves requested by the TLS client (RFC 8422, 5.1);
     * OpenSSL support via 'set_groups'/'set_curves':
     * https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set1_groups.html
     */
    CURLOPT_SSL_EC_CURVES = 10298,

    /* HSTS bitmask */
    CURLOPT_HSTS_CTRL = 299,
    /* HSTS file name */
    CURLOPT_HSTS = 10300,

    /* HSTS read callback */
    CURLOPT_HSTSREADFUNCTION = 20301,
    CURLOPT_HSTSREADDATA = 10302,

    /* HSTS write callback */
    CURLOPT_HSTSWRITEFUNCTION = 20303,
    CURLOPT_HSTSWRITEDATA = 10304,

    /* Parameters for V4 signature */
    CURLOPT_AWS_SIGV4 = 10305,

    /* Same as CURLOPT_SSL_VERIFYPEER but for DoH (DNS-over-HTTPS) servers. */
    CURLOPT_DOH_SSL_VERIFYPEER = 306,

    /* Same as CURLOPT_SSL_VERIFYHOST but for DoH (DNS-over-HTTPS) servers. */
    CURLOPT_DOH_SSL_VERIFYHOST = 307,

    /* Same as CURLOPT_SSL_VERIFYSTATUS but for DoH (DNS-over-HTTPS) servers. */
    CURLOPT_DOH_SSL_VERIFYSTATUS = 308,

    /* The CA certificates as "blob" used to validate the peer certificate
       this option is used only if SSL_VERIFYPEER is true */
    CURLOPT_CAINFO_BLOB = 40309,

    /* The CA certificates as "blob" used to validate the proxy certificate
       this option is used only if PROXY_SSL_VERIFYPEER is true */
    CURLOPT_PROXY_CAINFO_BLOB = 40310,

    /* used by scp/sftp to verify the host's public key */
    CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 = 10311,

    /* Function that will be called immediately before the initial request
       is made on a connection (after any protocol negotiation step).  */
    CURLOPT_PREREQFUNCTION = 20312,

    /* Data passed to the CURLOPT_PREREQFUNCTION callback */
    CURLOPT_PREREQDATA = 10313,

    /* maximum age (since creation) of a connection to consider it for reuse
     * (in seconds) */
    CURLOPT_MAXLIFETIME_CONN = 314,

    /* Set MIME option flags. */
    CURLOPT_MIME_OPTIONS = 315,

    /* set the SSH host key callback, must point to a curl_sshkeycallback
       function */
    CURLOPT_SSH_HOSTKEYFUNCTION = 20316,

    /* set the SSH host key callback custom pointer */
    CURLOPT_SSH_HOSTKEYDATA = 10317,

    /* specify which protocols that are allowed to be used for the transfer,
       which thus helps the app which takes URLs from users or other external
       inputs and want to restrict what protocol(s) to deal with. Defaults to
       all built-in protocols. */
    CURLOPT_PROTOCOLS_STR = 10318,

    /* specify which protocols that libcurl is allowed to follow directs to */
    CURLOPT_REDIR_PROTOCOLS_STR = 10319,

    /* websockets options */
    CURLOPT_WS_OPTIONS = 320,

    /* CA cache timeout */
    CURLOPT_CA_CACHE_TIMEOUT = 321,

    /* Can leak things, gonna exit() soon */
    CURLOPT_QUICK_EXIT = 322,

    /* set a specific client IP for HAProxy PROXY protocol header? */
    CURLOPT_HAPROXY_CLIENT_IP = 10323,

    CURLOPT_LASTENTRY /* the last unused */
}

enum CURLOPT_PROGRESSDATA = CURLoption.CURLOPT_XFERINFODATA;

/* define this to test if your app builds with all
   the obsolete stuff removed! */

/* Backwards compatibility with older names */
/* These are scheduled to disappear by 2011 */

/* This was added in version 7.19.1 */
enum CURLOPT_POST301 = CURLoption.CURLOPT_POSTREDIR;

/* These are scheduled to disappear by 2009 */

/* The following were added in 7.17.0 */
enum CURLOPT_SSLKEYPASSWD = CURLoption.CURLOPT_KEYPASSWD;
enum CURLOPT_FTPAPPEND = CURLoption.CURLOPT_APPEND;
enum CURLOPT_FTPLISTONLY = CURLoption.CURLOPT_DIRLISTONLY;
enum CURLOPT_FTP_SSL = CURLoption.CURLOPT_USE_SSL;

/* The following were added earlier */

enum CURLOPT_SSLCERTPASSWD = CURLoption.CURLOPT_KEYPASSWD;
enum CURLOPT_KRB4LEVEL = CURLoption.CURLOPT_KRBLEVEL;

/* */
enum CURLOPT_FTP_RESPONSE_TIMEOUT = CURLoption.CURLOPT_SERVER_RESPONSE_TIMEOUT;

/* Added in 8.2.0 */
enum CURLOPT_MAIL_RCPT_ALLLOWFAILS = CURLoption.CURLOPT_MAIL_RCPT_ALLOWFAILS;

/* This is set if CURL_NO_OLDIES is defined at compile-time */
/* soon obsolete */

/* Below here follows defines for the CURLOPT_IPRESOLVE option. If a host
   name resolves addresses using more than one IP protocol version, this
   option might be handy to force libcurl to use a specific IP version. */
enum CURL_IPRESOLVE_WHATEVER = 0; /* default, uses addresses to all IP
   versions that your system allows */
enum CURL_IPRESOLVE_V4 = 1; /* uses only IPv4 addresses/connections */
enum CURL_IPRESOLVE_V6 = 2; /* uses only IPv6 addresses/connections */

/* Convenient "aliases" */
enum CURLOPT_RTSPHEADER = CURLoption.CURLOPT_HTTPHEADER;

/* These enums are for use with the CURLOPT_HTTP_VERSION option. */
enum
{
    CURL_HTTP_VERSION_NONE = 0, /* setting this means we don't care, and that we'd
       like the library to choose the best possible
       for us! */
    CURL_HTTP_VERSION_1_0 = 1, /* please use HTTP 1.0 in the request */
    CURL_HTTP_VERSION_1_1 = 2, /* please use HTTP 1.1 in the request */
    CURL_HTTP_VERSION_2_0 = 3, /* please use HTTP 2 in the request */
    CURL_HTTP_VERSION_2TLS = 4, /* use version 2 for HTTPS, version 1.1 for HTTP */
    CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE = 5, /* please use HTTP 2 without HTTP/1.1
       Upgrade */
    CURL_HTTP_VERSION_3 = 30, /* Use HTTP/3, fallback to HTTP/2 or HTTP/1 if
       needed. For HTTPS only. For HTTP, this option
       makes libcurl return error. */
    CURL_HTTP_VERSION_3ONLY = 31, /* Use HTTP/3 without fallback. For HTTPS
       only. For HTTP, this makes libcurl
       return error. */

    CURL_HTTP_VERSION_LAST /* *ILLEGAL* http version */
}

/* Convenience definition simple because the name of the version is HTTP/2 and
   not 2.0. The 2_0 version of the enum name was set while the version was
   still planned to be 2.0 and we stick to it for compatibility. */
enum CURL_HTTP_VERSION_2 = .CURL_HTTP_VERSION_2_0;

/*
 * Public API enums for RTSP requests
 */
enum
{
    CURL_RTSPREQ_NONE = 0, /* first in list */
    CURL_RTSPREQ_OPTIONS = 1,
    CURL_RTSPREQ_DESCRIBE = 2,
    CURL_RTSPREQ_ANNOUNCE = 3,
    CURL_RTSPREQ_SETUP = 4,
    CURL_RTSPREQ_PLAY = 5,
    CURL_RTSPREQ_PAUSE = 6,
    CURL_RTSPREQ_TEARDOWN = 7,
    CURL_RTSPREQ_GET_PARAMETER = 8,
    CURL_RTSPREQ_SET_PARAMETER = 9,
    CURL_RTSPREQ_RECORD = 10,
    CURL_RTSPREQ_RECEIVE = 11,
    CURL_RTSPREQ_LAST /* last in list */
}

/* These enums are for use with the CURLOPT_NETRC option. */
enum CURL_NETRC_OPTION
{
    CURL_NETRC_IGNORED = 0, /* The .netrc will never be read.
     * This is the default. */
    CURL_NETRC_OPTIONAL = 1, /* A user:password in the URL will be preferred
     * to one in the .netrc. */
    CURL_NETRC_REQUIRED = 2, /* A user:password in the URL will be ignored.
     * Unless one is set programmatically, the .netrc
     * will be queried. */
    CURL_NETRC_LAST
}

enum
{
    CURL_SSLVERSION_DEFAULT = 0,
    CURL_SSLVERSION_TLSv1 = 1, /* TLS 1.x */
    CURL_SSLVERSION_SSLv2 = 2,
    CURL_SSLVERSION_SSLv3 = 3,
    CURL_SSLVERSION_TLSv1_0 = 4,
    CURL_SSLVERSION_TLSv1_1 = 5,
    CURL_SSLVERSION_TLSv1_2 = 6,
    CURL_SSLVERSION_TLSv1_3 = 7,

    CURL_SSLVERSION_LAST /* never use, keep last */
}

enum
{
    CURL_SSLVERSION_MAX_NONE = 0,
    CURL_SSLVERSION_MAX_DEFAULT = .CURL_SSLVERSION_TLSv1 << 16,
    CURL_SSLVERSION_MAX_TLSv1_0 = .CURL_SSLVERSION_TLSv1_0 << 16,
    CURL_SSLVERSION_MAX_TLSv1_1 = .CURL_SSLVERSION_TLSv1_1 << 16,
    CURL_SSLVERSION_MAX_TLSv1_2 = .CURL_SSLVERSION_TLSv1_2 << 16,
    CURL_SSLVERSION_MAX_TLSv1_3 = .CURL_SSLVERSION_TLSv1_3 << 16,

    /* never use, keep last */
    CURL_SSLVERSION_MAX_LAST = .CURL_SSLVERSION_LAST << 16
}

enum CURL_TLSAUTH
{
    CURL_TLSAUTH_NONE = 0,
    CURL_TLSAUTH_SRP = 1,
    CURL_TLSAUTH_LAST /* never use, keep last */
}

/* symbols to use with CURLOPT_POSTREDIR.
   CURL_REDIR_POST_301, CURL_REDIR_POST_302 and CURL_REDIR_POST_303
   can be bitwise ORed so that CURL_REDIR_POST_301 | CURL_REDIR_POST_302
   | CURL_REDIR_POST_303 == CURL_REDIR_POST_ALL */

enum CURL_REDIR_GET_ALL = 0;
enum CURL_REDIR_POST_301 = 1;
enum CURL_REDIR_POST_302 = 2;
enum CURL_REDIR_POST_303 = 4;
enum CURL_REDIR_POST_ALL = CURL_REDIR_POST_301 | CURL_REDIR_POST_302 | CURL_REDIR_POST_303;

enum curl_TimeCond
{
    CURL_TIMECOND_NONE = 0,

    CURL_TIMECOND_IFMODSINCE = 1,
    CURL_TIMECOND_IFUNMODSINCE = 2,
    CURL_TIMECOND_LASTMOD = 3,

    CURL_TIMECOND_LAST
}

/* Special size_t value signaling a null-terminated string. */
enum CURL_ZERO_TERMINATED = cast(size_t) -1;

/* curl_strequal() and curl_strnequal() are subject for removal in a future
   release */
int curl_strequal (const(char)* s1, const(char)* s2);
int curl_strnequal (const(char)* s1, const(char)* s2, size_t n);

/* Mime/form handling support. */
struct curl_mime; /* Mime context. */
struct curl_mimepart; /* Mime part context. */

/* CURLMIMEOPT_ defines are for the CURLOPT_MIME_OPTIONS option. */
enum CURLMIMEOPT_FORMESCAPE = 1 << 0; /* Use backslash-escaping for forms. */

/*
 * NAME curl_mime_init()
 *
 * DESCRIPTION
 *
 * Create a mime context and return its handle. The easy parameter is the
 * target handle.
 */
curl_mime* curl_mime_init (CURL* easy);

/*
 * NAME curl_mime_free()
 *
 * DESCRIPTION
 *
 * release a mime handle and its substructures.
 */
void curl_mime_free (curl_mime* mime);

/*
 * NAME curl_mime_addpart()
 *
 * DESCRIPTION
 *
 * Append a new empty part to the given mime context and return a handle to
 * the created part.
 */
curl_mimepart* curl_mime_addpart (curl_mime* mime);

/*
 * NAME curl_mime_name()
 *
 * DESCRIPTION
 *
 * Set mime/form part name.
 */
CURLcode curl_mime_name (curl_mimepart* part, const(char)* name);

/*
 * NAME curl_mime_filename()
 *
 * DESCRIPTION
 *
 * Set mime part remote file name.
 */
CURLcode curl_mime_filename (curl_mimepart* part, const(char)* filename);

/*
 * NAME curl_mime_type()
 *
 * DESCRIPTION
 *
 * Set mime part type.
 */
CURLcode curl_mime_type (curl_mimepart* part, const(char)* mimetype);

/*
 * NAME curl_mime_encoder()
 *
 * DESCRIPTION
 *
 * Set mime data transfer encoder.
 */
CURLcode curl_mime_encoder (curl_mimepart* part, const(char)* encoding);

/*
 * NAME curl_mime_data()
 *
 * DESCRIPTION
 *
 * Set mime part data source from memory data,
 */
CURLcode curl_mime_data (
    curl_mimepart* part,
    const(char)* data,
    size_t datasize);

/*
 * NAME curl_mime_filedata()
 *
 * DESCRIPTION
 *
 * Set mime part data source from named file.
 */
CURLcode curl_mime_filedata (curl_mimepart* part, const(char)* filename);

/*
 * NAME curl_mime_data_cb()
 *
 * DESCRIPTION
 *
 * Set mime part data source from callback function.
 */
CURLcode curl_mime_data_cb (
    curl_mimepart* part,
    curl_off_t datasize,
    curl_read_callback readfunc,
    curl_seek_callback seekfunc,
    curl_free_callback freefunc,
    void* arg);

/*
 * NAME curl_mime_subparts()
 *
 * DESCRIPTION
 *
 * Set mime part data source from subparts.
 */
CURLcode curl_mime_subparts (curl_mimepart* part, curl_mime* subparts);
/*
 * NAME curl_mime_headers()
 *
 * DESCRIPTION
 *
 * Set mime part headers.
 */
CURLcode curl_mime_headers (
    curl_mimepart* part,
    curl_slist* headers,
    int take_ownership);

enum CURLformoption
{
    /********* the first one is unused ************/
    CURLFORM_NOTHING = 0,
    CURLFORM_COPYNAME = 1,
    CURLFORM_PTRNAME = 2,
    CURLFORM_NAMELENGTH = 3,
    CURLFORM_COPYCONTENTS = 4,
    CURLFORM_PTRCONTENTS = 5,
    CURLFORM_CONTENTSLENGTH = 6,
    CURLFORM_FILECONTENT = 7,
    CURLFORM_ARRAY = 8,
    CURLFORM_OBSOLETE = 9,
    CURLFORM_FILE = 10,

    CURLFORM_BUFFER = 11,
    CURLFORM_BUFFERPTR = 12,
    CURLFORM_BUFFERLENGTH = 13,

    CURLFORM_CONTENTTYPE = 14,
    CURLFORM_CONTENTHEADER = 15,
    CURLFORM_FILENAME = 16,
    CURLFORM_END = 17,
    CURLFORM_OBSOLETE2 = 18,

    CURLFORM_STREAM = 19,
    CURLFORM_CONTENTLEN = 20, /* added in 7.46.0, provide a curl_off_t length */

    CURLFORM_LASTENTRY /* the last unused */
}

/* structure to be used as parameter for CURLFORM_ARRAY */
struct curl_forms
{
    CURLformoption option;
    const(char)* value;
}

/* use this for multipart formpost building */
/* Returns code for curl_formadd()
 *
 * Returns:
 * CURL_FORMADD_OK             on success
 * CURL_FORMADD_MEMORY         if the FormInfo allocation fails
 * CURL_FORMADD_OPTION_TWICE   if one option is given twice for one Form
 * CURL_FORMADD_NULL           if a null pointer was given for a char
 * CURL_FORMADD_MEMORY         if the allocation of a FormInfo struct failed
 * CURL_FORMADD_UNKNOWN_OPTION if an unknown option was used
 * CURL_FORMADD_INCOMPLETE     if the some FormInfo is not complete (or error)
 * CURL_FORMADD_MEMORY         if a curl_httppost struct cannot be allocated
 * CURL_FORMADD_MEMORY         if some allocation for string copying failed.
 * CURL_FORMADD_ILLEGAL_ARRAY  if an illegal option is used in an array
 *
 ***************************************************************************/
enum CURLFORMcode
{
    CURL_FORMADD_OK = 0, /* 1st, no error */

    CURL_FORMADD_MEMORY = 1,
    CURL_FORMADD_OPTION_TWICE = 2,
    CURL_FORMADD_NULL = 3,
    CURL_FORMADD_UNKNOWN_OPTION = 4,
    CURL_FORMADD_INCOMPLETE = 5,
    CURL_FORMADD_ILLEGAL_ARRAY = 6,
    /* libcurl was built with form api disabled */
    CURL_FORMADD_DISABLED = 7,

    CURL_FORMADD_LAST /* last */
}

/*
 * NAME curl_formadd()
 *
 * DESCRIPTION
 *
 * Pretty advanced function for building multi-part formposts. Each invoke
 * adds one part that together construct a full post. Then use
 * CURLOPT_HTTPPOST to send it off to libcurl.
 */
CURLFORMcode curl_formadd (
    curl_httppost** httppost,
    curl_httppost** last_post,
    ...);

/*
 * callback function for curl_formget()
 * The void *arg pointer will be the one passed as second argument to
 *   curl_formget().
 * The character buffer passed to it must not be freed.
 * Should return the buffer length passed to it as the argument "len" on
 *   success.
 */
alias curl_formget_callback = c_ulong function (
    void* arg,
    const(char)* buf,
    size_t len);

/*
 * NAME curl_formget()
 *
 * DESCRIPTION
 *
 * Serialize a curl_httppost struct built with curl_formadd().
 * Accepts a void pointer as second argument which will be passed to
 * the curl_formget_callback function.
 * Returns 0 on success.
 */
int curl_formget (curl_httppost* form, void* arg, curl_formget_callback append);
/*
 * NAME curl_formfree()
 *
 * DESCRIPTION
 *
 * Free a multipart formpost previously built with curl_formadd().
 */
void curl_formfree (curl_httppost* form);

/*
 * NAME curl_getenv()
 *
 * DESCRIPTION
 *
 * Returns a malloc()'ed string that MUST be curl_free()ed after usage is
 * complete. DEPRECATED - see lib/README.curlx
 */
char* curl_getenv (const(char)* variable);

/*
 * NAME curl_version()
 *
 * DESCRIPTION
 *
 * Returns a static ascii string of the libcurl version.
 */
char* curl_version ();

/*
 * NAME curl_easy_escape()
 *
 * DESCRIPTION
 *
 * Escapes URL strings (converts all letters consider illegal in URLs to their
 * %XX versions). This function returns a new allocated string or NULL if an
 * error occurred.
 */
char* curl_easy_escape (CURL* handle, const(char)* string, int length);

/* the previous version: */
char* curl_escape (const(char)* string, int length);

/*
 * NAME curl_easy_unescape()
 *
 * DESCRIPTION
 *
 * Unescapes URL encoding in strings (converts all %XX codes to their 8bit
 * versions). This function returns a new allocated string or NULL if an error
 * occurred.
 * Conversion Note: On non-ASCII platforms the ASCII %XX codes are
 * converted into the host encoding.
 */
char* curl_easy_unescape (
    CURL* handle,
    const(char)* string,
    int length,
    int* outlength);

/* the previous version */
char* curl_unescape (const(char)* string, int length);

/*
 * NAME curl_free()
 *
 * DESCRIPTION
 *
 * Provided for de-allocation in the same translation unit that did the
 * allocation. Added in libcurl 7.10
 */
void curl_free (void* p);

/*
 * NAME curl_global_init()
 *
 * DESCRIPTION
 *
 * curl_global_init() should be invoked exactly once for each application that
 * uses libcurl and before any call of other libcurl functions.

 * This function is thread-safe if CURL_VERSION_THREADSAFE is set in the
 * curl_version_info_data.features flag (fetch by curl_version_info()).

 */
CURLcode curl_global_init (c_long flags);

/*
 * NAME curl_global_init_mem()
 *
 * DESCRIPTION
 *
 * curl_global_init() or curl_global_init_mem() should be invoked exactly once
 * for each application that uses libcurl.  This function can be used to
 * initialize libcurl and set user defined memory management callback
 * functions.  Users can implement memory management routines to check for
 * memory leaks, check for mis-use of the curl library etc.  User registered
 * callback routines will be invoked by this library instead of the system
 * memory management routines like malloc, free etc.
 */
CURLcode curl_global_init_mem (
    c_long flags,
    curl_malloc_callback m,
    curl_free_callback f,
    curl_realloc_callback r,
    curl_strdup_callback s,
    curl_calloc_callback c);

/*
 * NAME curl_global_cleanup()
 *
 * DESCRIPTION
 *
 * curl_global_cleanup() should be invoked exactly once for each application
 * that uses libcurl
 */
void curl_global_cleanup ();

/*
 * NAME curl_global_trace()
 *
 * DESCRIPTION
 *
 * curl_global_trace() can be invoked at application start to
 * configure which components in curl should participate in tracing.

 * This function is thread-safe if CURL_VERSION_THREADSAFE is set in the
 * curl_version_info_data.features flag (fetch by curl_version_info()).

 */
CURLcode curl_global_trace (const(char)* config);

/* linked-list structure for the CURLOPT_QUOTE option (and other) */
struct curl_slist
{
    char* data;
    curl_slist* next;
}

/*
 * NAME curl_global_sslset()
 *
 * DESCRIPTION
 *
 * When built with multiple SSL backends, curl_global_sslset() allows to
 * choose one. This function can only be called once, and it must be called
 * *before* curl_global_init().
 *
 * The backend can be identified by the id (e.g. CURLSSLBACKEND_OPENSSL). The
 * backend can also be specified via the name parameter (passing -1 as id).
 * If both id and name are specified, the name will be ignored. If neither id
 * nor name are specified, the function will fail with
 * CURLSSLSET_UNKNOWN_BACKEND and set the "avail" pointer to the
 * NULL-terminated list of available backends.
 *
 * Upon success, the function returns CURLSSLSET_OK.
 *
 * If the specified SSL backend is not available, the function returns
 * CURLSSLSET_UNKNOWN_BACKEND and sets the "avail" pointer to a NULL-terminated
 * list of available SSL backends.
 *
 * The SSL backend can be set only once. If it has already been set, a
 * subsequent attempt to change it will result in a CURLSSLSET_TOO_LATE.
 */

struct curl_ssl_backend
{
    curl_sslbackend id;
    const(char)* name;
}

enum CURLsslset
{
    CURLSSLSET_OK = 0,
    CURLSSLSET_UNKNOWN_BACKEND = 1,
    CURLSSLSET_TOO_LATE = 2,
    CURLSSLSET_NO_BACKENDS = 3 /* libcurl was built without any SSL support */
}

CURLsslset curl_global_sslset (
    curl_sslbackend id,
    const(char)* name,
    const(curl_ssl_backend**)* avail);

/*
 * NAME curl_slist_append()
 *
 * DESCRIPTION
 *
 * Appends a string to a linked list. If no list exists, it will be created
 * first. Returns the new list, after appending.
 */
curl_slist* curl_slist_append (curl_slist* list, const(char)* data);

/*
 * NAME curl_slist_free_all()
 *
 * DESCRIPTION
 *
 * free a previously built curl_slist.
 */
void curl_slist_free_all (curl_slist* list);

/*
 * NAME curl_getdate()
 *
 * DESCRIPTION
 *
 * Returns the time, in seconds since 1 Jan 1970 of the time string given in
 * the first argument. The time argument in the second parameter is unused
 * and should be set to NULL.
 */
time_t curl_getdate (const(char)* p, const(time_t)* unused);

/* info about the certificate chain, for SSL backends that support it. Asked
   for with CURLOPT_CERTINFO / CURLINFO_CERTINFO */
struct curl_certinfo
{
    int num_of_certs; /* number of certificates with information */
    curl_slist** certinfo; /* for each index in this array, there's a
       linked list with textual information for a
       certificate in the format "name:content".
       eg "Subject:foo", "Issuer:bar", etc. */
}

/* Information about the SSL library used and the respective internal SSL
   handle, which can be used to obtain further information regarding the
   connection. Asked for with CURLINFO_TLS_SSL_PTR or CURLINFO_TLS_SESSION. */
struct curl_tlssessioninfo
{
    curl_sslbackend backend;
    void* internals;
}

enum CURLINFO_STRING = 0x100000;
enum CURLINFO_LONG = 0x200000;
enum CURLINFO_DOUBLE = 0x300000;
enum CURLINFO_SLIST = 0x400000;
enum CURLINFO_PTR = 0x400000; /* same as SLIST */
enum CURLINFO_SOCKET = 0x500000;
enum CURLINFO_OFF_T = 0x600000;
enum CURLINFO_MASK = 0x0fffff;
enum CURLINFO_TYPEMASK = 0xf00000;

enum CURLINFO
{
    CURLINFO_NONE = 0, /* first, never use this */
    CURLINFO_EFFECTIVE_URL = CURLINFO_STRING + 1,
    CURLINFO_RESPONSE_CODE = CURLINFO_LONG + 2,
    CURLINFO_TOTAL_TIME = CURLINFO_DOUBLE + 3,
    CURLINFO_NAMELOOKUP_TIME = CURLINFO_DOUBLE + 4,
    CURLINFO_CONNECT_TIME = CURLINFO_DOUBLE + 5,
    CURLINFO_PRETRANSFER_TIME = CURLINFO_DOUBLE + 6,
    CURLINFO_SIZE_UPLOAD = 3145735,
    CURLINFO_SIZE_UPLOAD_T = CURLINFO_OFF_T + 7,
    CURLINFO_SIZE_DOWNLOAD = 3145736,
    CURLINFO_SIZE_DOWNLOAD_T = CURLINFO_OFF_T + 8,
    CURLINFO_SPEED_DOWNLOAD = 3145737,
    CURLINFO_SPEED_DOWNLOAD_T = CURLINFO_OFF_T + 9,
    CURLINFO_SPEED_UPLOAD = 3145738,
    CURLINFO_SPEED_UPLOAD_T = CURLINFO_OFF_T + 10,
    CURLINFO_HEADER_SIZE = CURLINFO_LONG + 11,
    CURLINFO_REQUEST_SIZE = CURLINFO_LONG + 12,
    CURLINFO_SSL_VERIFYRESULT = CURLINFO_LONG + 13,
    CURLINFO_FILETIME = CURLINFO_LONG + 14,
    CURLINFO_FILETIME_T = CURLINFO_OFF_T + 14,
    CURLINFO_CONTENT_LENGTH_DOWNLOAD = 3145743,
    CURLINFO_CONTENT_LENGTH_DOWNLOAD_T = CURLINFO_OFF_T + 15,
    CURLINFO_CONTENT_LENGTH_UPLOAD = 3145744,
    CURLINFO_CONTENT_LENGTH_UPLOAD_T = CURLINFO_OFF_T + 16,
    CURLINFO_STARTTRANSFER_TIME = CURLINFO_DOUBLE + 17,
    CURLINFO_CONTENT_TYPE = CURLINFO_STRING + 18,
    CURLINFO_REDIRECT_TIME = CURLINFO_DOUBLE + 19,
    CURLINFO_REDIRECT_COUNT = CURLINFO_LONG + 20,
    CURLINFO_PRIVATE = CURLINFO_STRING + 21,
    CURLINFO_HTTP_CONNECTCODE = CURLINFO_LONG + 22,
    CURLINFO_HTTPAUTH_AVAIL = CURLINFO_LONG + 23,
    CURLINFO_PROXYAUTH_AVAIL = CURLINFO_LONG + 24,
    CURLINFO_OS_ERRNO = CURLINFO_LONG + 25,
    CURLINFO_NUM_CONNECTS = CURLINFO_LONG + 26,
    CURLINFO_SSL_ENGINES = CURLINFO_SLIST + 27,
    CURLINFO_COOKIELIST = CURLINFO_SLIST + 28,
    CURLINFO_LASTSOCKET = 2097181,
    CURLINFO_FTP_ENTRY_PATH = CURLINFO_STRING + 30,
    CURLINFO_REDIRECT_URL = CURLINFO_STRING + 31,
    CURLINFO_PRIMARY_IP = CURLINFO_STRING + 32,
    CURLINFO_APPCONNECT_TIME = CURLINFO_DOUBLE + 33,
    CURLINFO_CERTINFO = CURLINFO_PTR + 34,
    CURLINFO_CONDITION_UNMET = CURLINFO_LONG + 35,
    CURLINFO_RTSP_SESSION_ID = CURLINFO_STRING + 36,
    CURLINFO_RTSP_CLIENT_CSEQ = CURLINFO_LONG + 37,
    CURLINFO_RTSP_SERVER_CSEQ = CURLINFO_LONG + 38,
    CURLINFO_RTSP_CSEQ_RECV = CURLINFO_LONG + 39,
    CURLINFO_PRIMARY_PORT = CURLINFO_LONG + 40,
    CURLINFO_LOCAL_IP = CURLINFO_STRING + 41,
    CURLINFO_LOCAL_PORT = CURLINFO_LONG + 42,
    CURLINFO_TLS_SESSION = 4194347,
    CURLINFO_ACTIVESOCKET = CURLINFO_SOCKET + 44,
    CURLINFO_TLS_SSL_PTR = CURLINFO_PTR + 45,
    CURLINFO_HTTP_VERSION = CURLINFO_LONG + 46,
    CURLINFO_PROXY_SSL_VERIFYRESULT = CURLINFO_LONG + 47,
    CURLINFO_PROTOCOL = 2097200,
    CURLINFO_SCHEME = CURLINFO_STRING + 49,
    CURLINFO_TOTAL_TIME_T = CURLINFO_OFF_T + 50,
    CURLINFO_NAMELOOKUP_TIME_T = CURLINFO_OFF_T + 51,
    CURLINFO_CONNECT_TIME_T = CURLINFO_OFF_T + 52,
    CURLINFO_PRETRANSFER_TIME_T = CURLINFO_OFF_T + 53,
    CURLINFO_STARTTRANSFER_TIME_T = CURLINFO_OFF_T + 54,
    CURLINFO_REDIRECT_TIME_T = CURLINFO_OFF_T + 55,
    CURLINFO_APPCONNECT_TIME_T = CURLINFO_OFF_T + 56,
    CURLINFO_RETRY_AFTER = CURLINFO_OFF_T + 57,
    CURLINFO_EFFECTIVE_METHOD = CURLINFO_STRING + 58,
    CURLINFO_PROXY_ERROR = CURLINFO_LONG + 59,
    CURLINFO_REFERER = CURLINFO_STRING + 60,
    CURLINFO_CAINFO = CURLINFO_STRING + 61,
    CURLINFO_CAPATH = CURLINFO_STRING + 62,
    CURLINFO_XFER_ID = CURLINFO_OFF_T + 63,
    CURLINFO_CONN_ID = CURLINFO_OFF_T + 64,
    CURLINFO_LASTONE = 64
}

/* CURLINFO_RESPONSE_CODE is the new name for the option previously known as
   CURLINFO_HTTP_CODE */
enum CURLINFO_HTTP_CODE = CURLINFO.CURLINFO_RESPONSE_CODE;

enum curl_closepolicy
{
    CURLCLOSEPOLICY_NONE = 0, /* first, never use this */

    CURLCLOSEPOLICY_OLDEST = 1,
    CURLCLOSEPOLICY_LEAST_RECENTLY_USED = 2,
    CURLCLOSEPOLICY_LEAST_TRAFFIC = 3,
    CURLCLOSEPOLICY_SLOWEST = 4,
    CURLCLOSEPOLICY_CALLBACK = 5,

    CURLCLOSEPOLICY_LAST /* last, never use this */
}

enum CURL_GLOBAL_SSL = 1 << 0; /* no purpose since 7.57.0 */
enum CURL_GLOBAL_WIN32 = 1 << 1;
enum CURL_GLOBAL_ALL = CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32;
enum CURL_GLOBAL_NOTHING = 0;
enum CURL_GLOBAL_DEFAULT = CURL_GLOBAL_ALL;
enum CURL_GLOBAL_ACK_EINTR = 1 << 2;

/*****************************************************************************
 * Setup defines, protos etc for the sharing stuff.
 */

/* Different data locks for a single share */
enum curl_lock_data
{
    CURL_LOCK_DATA_NONE = 0,
    /*  CURL_LOCK_DATA_SHARE is used internally to say that
     *  the locking is just made to change the internal state of the share
     *  itself.
     */
    CURL_LOCK_DATA_SHARE = 1,
    CURL_LOCK_DATA_COOKIE = 2,
    CURL_LOCK_DATA_DNS = 3,
    CURL_LOCK_DATA_SSL_SESSION = 4,
    CURL_LOCK_DATA_CONNECT = 5,
    CURL_LOCK_DATA_PSL = 6,
    CURL_LOCK_DATA_HSTS = 7,
    CURL_LOCK_DATA_LAST
}

/* Different lock access types */
enum curl_lock_access
{
    CURL_LOCK_ACCESS_NONE = 0, /* unspecified action */
    CURL_LOCK_ACCESS_SHARED = 1, /* for read perhaps */
    CURL_LOCK_ACCESS_SINGLE = 2, /* for write perhaps */
    CURL_LOCK_ACCESS_LAST /* never use */
}

alias curl_lock_function = void function (
    CURL* handle,
    curl_lock_data data,
    curl_lock_access locktype,
    void* userptr);
alias curl_unlock_function = void function (
    CURL* handle,
    curl_lock_data data,
    void* userptr);

enum CURLSHcode
{
    CURLSHE_OK = 0, /* all is fine */
    CURLSHE_BAD_OPTION = 1, /* 1 */
    CURLSHE_IN_USE = 2, /* 2 */
    CURLSHE_INVALID = 3, /* 3 */
    CURLSHE_NOMEM = 4, /* 4 out of memory */
    CURLSHE_NOT_BUILT_IN = 5, /* 5 feature not present in lib */
    CURLSHE_LAST /* never use */
}

enum CURLSHoption
{
    CURLSHOPT_NONE = 0, /* don't use */
    CURLSHOPT_SHARE = 1, /* specify a data type to share */
    CURLSHOPT_UNSHARE = 2, /* specify which data type to stop sharing */
    CURLSHOPT_LOCKFUNC = 3, /* pass in a 'curl_lock_function' pointer */
    CURLSHOPT_UNLOCKFUNC = 4, /* pass in a 'curl_unlock_function' pointer */
    CURLSHOPT_USERDATA = 5, /* pass in a user data pointer used in the lock/unlock
       callback functions */
    CURLSHOPT_LAST /* never use */
}

CURLSH* curl_share_init ();
CURLSHcode curl_share_setopt (CURLSH* share, CURLSHoption option, ...);
CURLSHcode curl_share_cleanup (CURLSH* share);

/****************************************************************************
 * Structures for querying information about the curl library at runtime.
 */

enum CURLversion
{
    CURLVERSION_FIRST = 0,
    CURLVERSION_SECOND = 1,
    CURLVERSION_THIRD = 2,
    CURLVERSION_FOURTH = 3,
    CURLVERSION_FIFTH = 4,
    CURLVERSION_SIXTH = 5,
    CURLVERSION_SEVENTH = 6,
    CURLVERSION_EIGHTH = 7,
    CURLVERSION_NINTH = 8,
    CURLVERSION_TENTH = 9,
    CURLVERSION_ELEVENTH = 10,
    CURLVERSION_LAST /* never actually use this */
}

/* The 'CURLVERSION_NOW' is the symbolic name meant to be used by
   basically all programs ever that want to get version information. It is
   meant to be a built-in version number for what kind of struct the caller
   expects. If the struct ever changes, we redefine the NOW to another enum
   from above. */
enum CURLVERSION_NOW = CURLversion.CURLVERSION_ELEVENTH;

struct curl_version_info_data
{
    CURLversion age; /* age of the returned struct */
    const(char)* version_; /* LIBCURL_VERSION */
    uint version_num; /* LIBCURL_VERSION_NUM */
    const(char)* host; /* OS/host/cpu/machine when configured */
    int features; /* bitmask, see defines below */
    const(char)* ssl_version; /* human readable string */
    c_long ssl_version_num; /* not used anymore, always 0 */
    const(char)* libz_version; /* human readable string */
    /* protocols is terminated by an entry with a NULL protoname */
    const(char*)* protocols;

    /* The fields below this were added in CURLVERSION_SECOND */
    const(char)* ares;
    int ares_num;

    /* This field was added in CURLVERSION_THIRD */
    const(char)* libidn;

    /* These field were added in CURLVERSION_FOURTH */

    /* Same as '_libiconv_version' if built with HAVE_ICONV */
    int iconv_ver_num;

    const(char)* libssh_version; /* human readable string */

    /* These fields were added in CURLVERSION_FIFTH */
    uint brotli_ver_num; /* Numeric Brotli version
       (MAJOR << 24) | (MINOR << 12) | PATCH */
    const(char)* brotli_version; /* human readable string. */

    /* These fields were added in CURLVERSION_SIXTH */
    uint nghttp2_ver_num; /* Numeric nghttp2 version
       (MAJOR << 16) | (MINOR << 8) | PATCH */
    const(char)* nghttp2_version; /* human readable string. */
    const(char)* quic_version; /* human readable quic (+ HTTP/3) library +
       version or NULL */

    /* These fields were added in CURLVERSION_SEVENTH */
    const(char)* cainfo; /* the built-in default CURLOPT_CAINFO, might
       be NULL */
    const(char)* capath; /* the built-in default CURLOPT_CAPATH, might
       be NULL */

    /* These fields were added in CURLVERSION_EIGHTH */
    uint zstd_ver_num; /* Numeric Zstd version
         (MAJOR << 24) | (MINOR << 12) | PATCH */
    const(char)* zstd_version; /* human readable string. */

    /* These fields were added in CURLVERSION_NINTH */
    const(char)* hyper_version; /* human readable string. */

    /* These fields were added in CURLVERSION_TENTH */
    const(char)* gsasl_version; /* human readable string. */

    /* These fields were added in CURLVERSION_ELEVENTH */
    /* feature_names is terminated by an entry with a NULL feature name */
    const(char*)* feature_names;
}

enum CURL_VERSION_IPV6 = 1 << 0; /* IPv6-enabled */
enum CURL_VERSION_KERBEROS4 = 1 << 1; /* Kerberos V4 auth is supported
   (deprecated) */
enum CURL_VERSION_SSL = 1 << 2; /* SSL options are present */
enum CURL_VERSION_LIBZ = 1 << 3; /* libz features are present */
enum CURL_VERSION_NTLM = 1 << 4; /* NTLM auth is supported */
enum CURL_VERSION_GSSNEGOTIATE = 1 << 5; /* Negotiate auth is supported
   (deprecated) */
enum CURL_VERSION_DEBUG = 1 << 6; /* Built with debug capabilities */
enum CURL_VERSION_ASYNCHDNS = 1 << 7; /* Asynchronous DNS resolves */
enum CURL_VERSION_SPNEGO = 1 << 8; /* SPNEGO auth is supported */
enum CURL_VERSION_LARGEFILE = 1 << 9; /* Supports files larger than 2GB */
enum CURL_VERSION_IDN = 1 << 10; /* Internationized Domain Names are
   supported */
enum CURL_VERSION_SSPI = 1 << 11; /* Built against Windows SSPI */
enum CURL_VERSION_CONV = 1 << 12; /* Character conversions supported */
enum CURL_VERSION_CURLDEBUG = 1 << 13; /* Debug memory tracking supported */
enum CURL_VERSION_TLSAUTH_SRP = 1 << 14; /* TLS-SRP auth is supported */
enum CURL_VERSION_NTLM_WB = 1 << 15; /* NTLM delegation to winbind helper
   is supported */
enum CURL_VERSION_HTTP2 = 1 << 16; /* HTTP2 support built-in */
enum CURL_VERSION_GSSAPI = 1 << 17; /* Built against a GSS-API library */
enum CURL_VERSION_KERBEROS5 = 1 << 18; /* Kerberos V5 auth is supported */
enum CURL_VERSION_UNIX_SOCKETS = 1 << 19; /* Unix domain sockets support */
enum CURL_VERSION_PSL = 1 << 20; /* Mozilla's Public Suffix List, used
   for cookie domain verification */
enum CURL_VERSION_HTTPS_PROXY = 1 << 21; /* HTTPS-proxy support built-in */
enum CURL_VERSION_MULTI_SSL = 1 << 22; /* Multiple SSL backends available */
enum CURL_VERSION_BROTLI = 1 << 23; /* Brotli features are present. */
enum CURL_VERSION_ALTSVC = 1 << 24; /* Alt-Svc handling built-in */
enum CURL_VERSION_HTTP3 = 1 << 25; /* HTTP3 support built-in */
enum CURL_VERSION_ZSTD = 1 << 26; /* zstd features are present */
enum CURL_VERSION_UNICODE = 1 << 27; /* Unicode support on Windows */
enum CURL_VERSION_HSTS = 1 << 28; /* HSTS is supported */
enum CURL_VERSION_GSASL = 1 << 29; /* libgsasl is supported */
enum CURL_VERSION_THREADSAFE = 1 << 30; /* libcurl API is thread-safe */

/*
* NAME curl_version_info()
*
* DESCRIPTION
*
* This function returns a pointer to a static copy of the version info
* struct. See above.
*/
curl_version_info_data* curl_version_info (CURLversion);

/*
 * NAME curl_easy_strerror()
 *
 * DESCRIPTION
 *
 * The curl_easy_strerror function may be used to turn a CURLcode value
 * into the equivalent human readable error string.  This is useful
 * for printing meaningful error messages.
 */
const(char)* curl_easy_strerror (CURLcode);

/*
 * NAME curl_share_strerror()
 *
 * DESCRIPTION
 *
 * The curl_share_strerror function may be used to turn a CURLSHcode value
 * into the equivalent human readable error string.  This is useful
 * for printing meaningful error messages.
 */
const(char)* curl_share_strerror (CURLSHcode);

/*
 * NAME curl_easy_pause()
 *
 * DESCRIPTION
 *
 * The curl_easy_pause function pauses or unpauses transfers. Select the new
 * state by setting the bitmask, use the convenience defines below.
 *
 */
CURLcode curl_easy_pause (CURL* handle, int bitmask);

enum CURLPAUSE_RECV = 1 << 0;
enum CURLPAUSE_RECV_CONT = 0;

enum CURLPAUSE_SEND = 1 << 2;
enum CURLPAUSE_SEND_CONT = 0;

enum CURLPAUSE_ALL = CURLPAUSE_RECV | CURLPAUSE_SEND;
enum CURLPAUSE_CONT = CURLPAUSE_RECV_CONT | CURLPAUSE_SEND_CONT;

/* end of extern "C" */

/* unfortunately, the easy.h and multi.h include files need options and info
  stuff before they can be included! */
public import ys3ds.curl.easy; /* nothing in curl is fun without the easy stuff */
public import ys3ds.curl.multi;
public import ys3ds.curl.urlapi;
public import ys3ds.curl.options;
public import ys3ds.curl.header;
public import ys3ds.curl.websockets;

/* the typechecker doesn't work in C++ (yet) */
// public import ys3ds.curl.typecheck_gcc;

/* This preprocessor magic that replaces a call with the exact same call is
   only done to make sure application authors pass exactly three arguments
   to these functions. */
// wait so why are these even vararg then? -- sink
// they're defined in other headers so this doesnt even work.
/* alias curl_easy_setopt = curl_easy_setopt;
alias curl_easy_getinfo = curl_easy_getinfo;
alias curl_share_setopt = curl_share_setopt;
alias curl_multi_setopt = curl_multi_setopt; */
/* __STDC__ >= 1 */
/* gcc >= 4.3 && !__cplusplus && !CURL_DISABLE_TYPECHECK */

/* CURLINC_CURL_H */
