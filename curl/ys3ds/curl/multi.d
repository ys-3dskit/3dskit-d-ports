module ys3ds.curl.multi;

import ys3ds.curl;

import core.stdc.config;
import core.sys.horizon.sys.select;

extern (C) @nogc nothrow:

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
  This is an "external" header file. Don't give away any internals here!

  GOALS

  o Enable a "pull" interface. The application that uses libcurl decides where
    and when to ask libcurl to get/send data.

  o Enable multiple simultaneous transfers in the same thread without making it
    complicated for the application.

  o Enable the application to select() on its own file descriptors and curl's
    file descriptors simultaneous easily.

*/

/*
 * This header file should not really need to include "curl.h" since curl.h
 * itself includes this file and we expect user applications to do #include
 * <curl/curl.h> without the need for especially including multi.h.
 *
 * For some reason we added this include here at one point, and rather than to
 * break existing (wrongly written) libcurl applications, we leave it as-is
 * but with this warning attached.
 */

alias CURLM = void;

enum CURLMcode
{
    CURLM_CALL_MULTI_PERFORM = -1, /* please call curl_multi_perform() or
       curl_multi_socket*() soon */
    CURLM_OK = 0,
    CURLM_BAD_HANDLE = 1, /* the passed-in handle is not a valid CURLM handle */
    CURLM_BAD_EASY_HANDLE = 2, /* an easy handle was not good/valid */
    CURLM_OUT_OF_MEMORY = 3, /* if you ever get this, you're in deep sh*t */
    CURLM_INTERNAL_ERROR = 4, /* this is a libcurl bug */
    CURLM_BAD_SOCKET = 5, /* the passed in socket argument did not match */
    CURLM_UNKNOWN_OPTION = 6, /* curl_multi_setopt() with unsupported option */
    CURLM_ADDED_ALREADY = 7, /* an easy handle already added to a multi handle was
       attempted to get added - again */
    CURLM_RECURSIVE_API_CALL = 8, /* an api function was called from inside a
       callback */
    CURLM_WAKEUP_FAILURE = 9, /* wakeup is unavailable or failed */
    CURLM_BAD_FUNCTION_ARGUMENT = 10, /* function called with a bad parameter */
    CURLM_ABORTED_BY_CALLBACK = 11,
    CURLM_UNRECOVERABLE_POLL = 12,
    CURLM_LAST
}

/* just to make code nicer when using curl_multi_socket() you can now check
   for CURLM_CALL_MULTI_SOCKET too in the same style it works for
   curl_multi_perform() and CURLM_CALL_MULTI_PERFORM */
enum CURLM_CALL_MULTI_SOCKET = CURLMcode.CURLM_CALL_MULTI_PERFORM;

/* bitmask bits for CURLMOPT_PIPELINING */
enum CURLPIPE_NOTHING = 0L;
enum CURLPIPE_HTTP1 = 1L;
enum CURLPIPE_MULTIPLEX = 2L;

enum CURLMSG
{
    CURLMSG_NONE = 0, /* first, not used */
    CURLMSG_DONE = 1, /* This easy handle has completed. 'result' contains
       the CURLcode of the transfer */
    CURLMSG_LAST /* last, not used */
}

struct CURLMsg
{
    CURLMSG msg; /* what this message means */
    CURL* easy_handle; /* the handle it concerns */

    /* message-specific data */
    /* return code for transfer */
    union _Anonymous_0
    {
        void* whatever;
        CURLcode result;
    }

    _Anonymous_0 data;
}

/* Based on poll(2) structure and values.
 * We don't use pollfd and POLL* constants explicitly
 * to cover platforms without poll(). */
enum CURL_WAIT_POLLIN = 0x0001;
enum CURL_WAIT_POLLPRI = 0x0002;
enum CURL_WAIT_POLLOUT = 0x0004;

struct curl_waitfd
{
    curl_socket_t fd;
    short events;
    short revents;
}

/*
 * Name:    curl_multi_init()
 *
 * Desc:    initialize multi-style curl usage
 *
 * Returns: a new CURLM handle to use in all 'curl_multi' functions.
 */
CURLM* curl_multi_init ();

/*
 * Name:    curl_multi_add_handle()
 *
 * Desc:    add a standard curl handle to the multi stack
 *
 * Returns: CURLMcode type, general multi error code.
 */
CURLMcode curl_multi_add_handle (CURLM* multi_handle, CURL* curl_handle);

/*
 * Name:    curl_multi_remove_handle()
 *
 * Desc:    removes a curl handle from the multi stack again
 *
 * Returns: CURLMcode type, general multi error code.
 */
CURLMcode curl_multi_remove_handle (CURLM* multi_handle, CURL* curl_handle);

/*
 * Name:    curl_multi_fdset()
 *
 * Desc:    Ask curl for its fd_set sets. The app can use these to select() or
 *          poll() on. We want curl_multi_perform() called as soon as one of
 *          them are ready.
 *
 * Returns: CURLMcode type, general multi error code.
 */
CURLMcode curl_multi_fdset (
    CURLM* multi_handle,
    fd_set* read_fd_set,
    fd_set* write_fd_set,
    fd_set* exc_fd_set,
    int* max_fd);

/*
 * Name:     curl_multi_wait()
 *
 * Desc:     Poll on all fds within a CURLM set as well as any
 *           additional fds passed to the function.
 *
 * Returns:  CURLMcode type, general multi error code.
 */
CURLMcode curl_multi_wait (
    CURLM* multi_handle,
    curl_waitfd* extra_fds,
    uint extra_nfds,
    int timeout_ms,
    int* ret);

/*
 * Name:     curl_multi_poll()
 *
 * Desc:     Poll on all fds within a CURLM set as well as any
 *           additional fds passed to the function.
 *
 * Returns:  CURLMcode type, general multi error code.
 */
CURLMcode curl_multi_poll (
    CURLM* multi_handle,
    curl_waitfd* extra_fds,
    uint extra_nfds,
    int timeout_ms,
    int* ret);

/*
 * Name:     curl_multi_wakeup()
 *
 * Desc:     wakes up a sleeping curl_multi_poll call.
 *
 * Returns:  CURLMcode type, general multi error code.
 */
CURLMcode curl_multi_wakeup (CURLM* multi_handle);

/*
 * Name:    curl_multi_perform()
 *
 * Desc:    When the app thinks there's data available for curl it calls this
 *          function to read/write whatever there is right now. This returns
 *          as soon as the reads and writes are done. This function does not
 *          require that there actually is data available for reading or that
 *          data can be written, it can be called just in case. It returns
 *          the number of handles that still transfer data in the second
 *          argument's integer-pointer.
 *
 * Returns: CURLMcode type, general multi error code. *NOTE* that this only
 *          returns errors etc regarding the whole multi stack. There might
 *          still have occurred problems on individual transfers even when
 *          this returns OK.
 */
CURLMcode curl_multi_perform (CURLM* multi_handle, int* running_handles);

/*
 * Name:    curl_multi_cleanup()
 *
 * Desc:    Cleans up and removes a whole multi stack. It does not free or
 *          touch any individual easy handles in any way. We need to define
 *          in what state those handles will be if this function is called
 *          in the middle of a transfer.
 *
 * Returns: CURLMcode type, general multi error code.
 */
CURLMcode curl_multi_cleanup (CURLM* multi_handle);

/*
 * Name:    curl_multi_info_read()
 *
 * Desc:    Ask the multi handle if there's any messages/informationals from
 *          the individual transfers. Messages include informationals such as
 *          error code from the transfer or just the fact that a transfer is
 *          completed. More details on these should be written down as well.
 *
 *          Repeated calls to this function will return a new struct each
 *          time, until a special "end of msgs" struct is returned as a signal
 *          that there is no more to get at this point.
 *
 *          The data the returned pointer points to will not survive calling
 *          curl_multi_cleanup().
 *
 *          The 'CURLMsg' struct is meant to be very simple and only contain
 *          very basic information. If more involved information is wanted,
 *          we will provide the particular "transfer handle" in that struct
 *          and that should/could/would be used in subsequent
 *          curl_easy_getinfo() calls (or similar). The point being that we
 *          must never expose complex structs to applications, as then we'll
 *          undoubtably get backwards compatibility problems in the future.
 *
 * Returns: A pointer to a filled-in struct, or NULL if it failed or ran out
 *          of structs. It also writes the number of messages left in the
 *          queue (after this read) in the integer the second argument points
 *          to.
 */
CURLMsg* curl_multi_info_read (CURLM* multi_handle, int* msgs_in_queue);

/*
 * Name:    curl_multi_strerror()
 *
 * Desc:    The curl_multi_strerror function may be used to turn a CURLMcode
 *          value into the equivalent human readable error string.  This is
 *          useful for printing meaningful error messages.
 *
 * Returns: A pointer to a null-terminated error message.
 */
const(char)* curl_multi_strerror (CURLMcode);

/*
 * Name:    curl_multi_socket() and
 *          curl_multi_socket_all()
 *
 * Desc:    An alternative version of curl_multi_perform() that allows the
 *          application to pass in one of the file descriptors that have been
 *          detected to have "action" on them and let libcurl perform.
 *          See man page for details.
 */
enum CURL_POLL_NONE = 0;
enum CURL_POLL_IN = 1;
enum CURL_POLL_OUT = 2;
enum CURL_POLL_INOUT = 3;
enum CURL_POLL_REMOVE = 4;

enum CURL_SOCKET_TIMEOUT = CURL_SOCKET_BAD;

enum CURL_CSELECT_IN = 0x01;
enum CURL_CSELECT_OUT = 0x02;
enum CURL_CSELECT_ERR = 0x04;

alias curl_socket_callback = int function (
    CURL* easy,      /* easy handle */
    curl_socket_t s, /* socket */
    int what,        /* see above */
    void* userp,     /* private callback
                        pointer */
    void* socketp);  /* private socket
                        pointer */
/*
 * Name:    curl_multi_timer_callback
 *
 * Desc:    Called by libcurl whenever the library detects a change in the
 *          maximum number of milliseconds the app is allowed to wait before
 *          curl_multi_socket() or curl_multi_perform() must be called
 *          (to allow libcurl's timed events to take place).
 *
 * Returns: The callback should return zero.
 */
/* multi handle */
/* see above */
alias curl_multi_timer_callback = int function (
    CURLM* multi,
    c_long timeout_ms,
    void* userp); /* private callback
   pointer */

CURLMcode curl_multi_socket (
    CURLM* multi_handle,
    curl_socket_t s,
    int* running_handles);

CURLMcode curl_multi_socket_action (
    CURLM* multi_handle,
    curl_socket_t s,
    int ev_bitmask,
    int* running_handles);

CURLMcode curl_multi_socket_all (CURLM* multi_handle, int* running_handles);

/* This macro below was added in 7.16.3 to push users who recompile to use
   the new curl_multi_socket_action() instead of the old curl_multi_socket()
*/
pragma(inline, true)
extern (D) auto curl_multi_socket(T0, T1, T2)(auto ref T0 x, auto ref T1 y, auto ref T2 z)
{
    return curl_multi_socket_action(x, y, 0, z);
}

/*
 * Name:    curl_multi_timeout()
 *
 * Desc:    Returns the maximum number of milliseconds the app is allowed to
 *          wait before curl_multi_socket() or curl_multi_perform() must be
 *          called (to allow libcurl's timed events to take place).
 *
 * Returns: CURLM error code.
 */
CURLMcode curl_multi_timeout (CURLM* multi_handle, c_long* milliseconds);

enum CURLMoption
{
    /* This is the socket callback function pointer */
    CURLMOPT_SOCKETFUNCTION = 20001,

    /* This is the argument passed to the socket callback */
    CURLMOPT_SOCKETDATA = 10002,

    /* set to 1 to enable pipelining for this multi handle */
    CURLMOPT_PIPELINING = 3,

    /* This is the timer callback function pointer */
    CURLMOPT_TIMERFUNCTION = 20004,

    /* This is the argument passed to the timer callback */
    CURLMOPT_TIMERDATA = 10005,

    /* maximum number of entries in the connection cache */
    CURLMOPT_MAXCONNECTS = 6,

    /* maximum number of (pipelining) connections to one host */
    CURLMOPT_MAX_HOST_CONNECTIONS = 7,

    /* maximum number of requests in a pipeline */
    CURLMOPT_MAX_PIPELINE_LENGTH = 8,

    /* a connection with a content-length longer than this
       will not be considered for pipelining */
    CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE = 30009,

    /* a connection with a chunk length longer than this
       will not be considered for pipelining */
    CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE = 30010,

    /* a list of site names(+port) that are blocked from pipelining */
    CURLMOPT_PIPELINING_SITE_BL = 10011,

    /* a list of server types that are blocked from pipelining */
    CURLMOPT_PIPELINING_SERVER_BL = 10012,

    /* maximum number of open connections in total */
    CURLMOPT_MAX_TOTAL_CONNECTIONS = 13,

    /* This is the server push callback function pointer */
    CURLMOPT_PUSHFUNCTION = 20014,

    /* This is the argument passed to the server push callback */
    CURLMOPT_PUSHDATA = 10015,

    /* maximum number of concurrent streams to support on a connection */
    CURLMOPT_MAX_CONCURRENT_STREAMS = 16,

    CURLMOPT_LASTENTRY /* the last unused */
}

/*
 * Name:    curl_multi_setopt()
 *
 * Desc:    Sets options for the multi handle.
 *
 * Returns: CURLM error code.
 */
CURLMcode curl_multi_setopt (CURLM* multi_handle, CURLMoption option, ...);

/*
 * Name:    curl_multi_assign()
 *
 * Desc:    This function sets an association in the multi handle between the
 *          given socket and a private pointer of the application. This is
 *          (only) useful for curl_multi_socket uses.
 *
 * Returns: CURLM error code.
 */
CURLMcode curl_multi_assign (
    CURLM* multi_handle,
    curl_socket_t sockfd,
    void* sockp);

/*
 * Name:    curl_multi_get_handles()
 *
 * Desc:    Returns an allocated array holding all handles currently added to
 *          the multi handle. Marks the final entry with a NULL pointer. If
 *          there is no easy handle added to the multi handle, this function
 *          returns an array with the first entry as a NULL pointer.
 *
 * Returns: NULL on failure, otherwise a CURL **array pointer
 */
CURL** curl_multi_get_handles (CURLM* multi_handle);

/*
 * Name: curl_push_callback
 *
 * Desc: This callback gets called when a new stream is being pushed by the
 *       server. It approves or denies the new stream. It can also decide
 *       to completely fail the connection.
 *
 * Returns: CURL_PUSH_OK, CURL_PUSH_DENY or CURL_PUSH_ERROROUT
 */
enum CURL_PUSH_OK = 0;
enum CURL_PUSH_DENY = 1;
enum CURL_PUSH_ERROROUT = 2; /* added in 7.72.0 */

struct curl_pushheaders; /* forward declaration only */

char* curl_pushheader_bynum (curl_pushheaders* h, size_t num);
char* curl_pushheader_byname (curl_pushheaders* h, const(char)* name);

alias curl_push_callback = int function (
    CURL* parent,
    CURL* easy,
    size_t num_headers,
    curl_pushheaders* headers,
    void* userp);

/* end of extern "C" */

