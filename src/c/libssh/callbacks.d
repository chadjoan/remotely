/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 Aris Adamantiadis <aris@0xbadc0de.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* callback.h
 * This file includes the public declarations for the libssh callback mechanism
 */

module c.libssh.callbacks;

public import c.libssh.libssh;

import core.stdc.config;

// For the callbacks themselves, we will be pretty liberal about function
// signatures.
// We don't want to assume anything about stack layout, so we mark these
// nothrow.  GC should be safe though, as long as D code keeps a pointer to
// any D memory floating around in LibSSH code.  Marking extern(C) would just
// be detrimental to the callbacks, because then you'd have to worry about
// C-style symbol collisions and all that mess.
nothrow:

/**
 * @defgroup libssh_callbacks The libssh callbacks
 * @ingroup libssh
 *
 * Callback which can be replaced in libssh.
 *
 * @{
 */

/** @internal
 * @brief callback to process simple codes
 * @param code value to transmit
 * @param user Userdata to pass in callback
 */
alias ssh_callback_int = void function(int code, void *user);

/** @internal
 * @brief callback for data received messages.
 * @param data data retrieved from the socket or stream
 * @param len number of bytes available from this stream
 * @param user user-supplied pointer sent along with all callback messages
 * @returns number of bytes processed by the callee. The remaining bytes will
 * be sent in the next callback message, when more data is available.
 */
alias ssh_callback_data = int function(const void *data, size_t len, void *user);

alias ssh_callback_int_int = void function(int code, int errno_code, void *user);

alias ssh_message_callback = int function(ssh_session, ssh_message message, void *user);
alias ssh_channel_callback_int = int function(ssh_channel channel, int code, void *user);
alias ssh_channel_callback_data = int function(ssh_channel channel, int code, void *data, size_t len, void *user);

/**
 * @brief SSH log callback. All logging messages will go through this callback
 * @param session Current session handler
 * @param priority Priority of the log, the smaller being the more important
 * @param message the actual message
 * @param userdata Userdata to be passed to the callback function.
 */
alias ssh_log_callback = void function(ssh_session session, int priority,
    const(char)* message, void *userdata);

/**
 * @brief SSH log callback.
 *
 * All logging messages will go through this callback.
 *
 * @param priority  Priority of the log, the smaller being the more important.
 *
 * @param function  The function name calling the the logging fucntions.
 *
 * @param message   The actual message
 *
 * @param userdata Userdata to be passed to the callback function.
 */
alias ssh_logging_callback = void function(int priority,
                                      const(char)* func,
                                      const(char)* buffer,
                                      void *userdata);

/**
 * @brief SSH Connection status callback.
 * @param session Current session handler
 * @param status Percentage of connection status, going from 0.0 to 1.0
 * once connection is done.
 * @param userdata Userdata to be passed to the callback function.
 */
alias ssh_status_callback = void function(ssh_session session, float status, void *userdata);

/**
 * @brief SSH global request callback. All global request will go through this
 * callback.
 * @param session Current session handler
 * @param message the actual message
 * @param userdata Userdata to be passed to the callback function.
 */
alias ssh_global_request_callback = void function(ssh_session session,
                                        ssh_message message, void *userdata);

/**
 * @brief Handles an SSH new channel open X11 request. This happens when the server
 * sends back an X11 connection attempt. This is a client-side API
 * @param session current session handler
 * @param userdata Userdata to be passed to the callback function.
 * @returns a valid ssh_channel handle if the request is to be allowed
 * @returns NULL if the request should not be allowed
 * @warning The channel pointer returned by this callback must be closed by the application.
 */
alias ssh_channel_open_request_x11_callback = ssh_channel function(ssh_session session,
      const(char)*  originator_address, int originator_port, void *userdata);

/** These are callbacks used specifically in SSH servers.
 */

/**
 * @brief SSH authentication callback.
 * @param session Current session handler
 * @param user User that wants to authenticate
 * @param password Password used for authentication
 * @param userdata Userdata to be passed to the callback function.
 * @returns SSH_AUTH_SUCCESS Authentication is accepted.
 * @returns SSH_AUTH_PARTIAL Partial authentication, more authentication means are needed.
 * @returns SSH_AUTH_DENIED Authentication failed.
 */
alias ssh_auth_password_callback = int function(ssh_session session, const(char)* user, const(char)* password,
		void *userdata);

/**
 * @brief SSH authentication callback. Tries to authenticates user with the "none" method
 * which is anonymous or passwordless.
 * @param session Current session handler
 * @param user User that wants to authenticate
 * @param userdata Userdata to be passed to the callback function.
 * @returns SSH_AUTH_SUCCESS Authentication is accepted.
 * @returns SSH_AUTH_PARTIAL Partial authentication, more authentication means are needed.
 * @returns SSH_AUTH_DENIED Authentication failed.
 */
alias ssh_auth_none_callback = int function(ssh_session session, const(char)* user, void *userdata);

/**
 * @brief SSH authentication callback. Tries to authenticates user with the "gssapi-with-mic" method
 * @param session Current session handler
 * @param user Username of the user (can be spoofed)
 * @param principal Authenticated principal of the user, including realm.
 * @param userdata Userdata to be passed to the callback function.
 * @returns SSH_AUTH_SUCCESS Authentication is accepted.
 * @returns SSH_AUTH_PARTIAL Partial authentication, more authentication means are needed.
 * @returns SSH_AUTH_DENIED Authentication failed.
 * @warning Implementations should verify that parameter user matches in some way the principal.
 * user and principal can be different. Only the latter is guaranteed to be safe.
 */
alias ssh_auth_gssapi_mic_callback = int function(ssh_session session, const(char)* user, const(char)* principal,
		void *userdata);

/**
 * @brief SSH authentication callback.
 * @param session Current session handler
 * @param user User that wants to authenticate
 * @param pubkey public key used for authentication
 * @param signature_state SSH_PUBLICKEY_STATE_NONE if the key is not signed (simple public key probe),
 * 							SSH_PUBLICKEY_STATE_VALID if the signature is valid. Others values should be
 * 							replied with a SSH_AUTH_DENIED.
 * @param userdata Userdata to be passed to the callback function.
 * @returns SSH_AUTH_SUCCESS Authentication is accepted.
 * @returns SSH_AUTH_PARTIAL Partial authentication, more authentication means are needed.
 * @returns SSH_AUTH_DENIED Authentication failed.
 */
alias ssh_auth_pubkey_callback = int function(ssh_session session, const(char)* user, ssh_key_struct *pubkey,
		char signature_state, void *userdata);


/**
 * @brief Handles an SSH service request
 * @param session current session handler
 * @param service name of the service (e.g. "ssh-userauth") requested
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the request is to be allowed
 * @returns -1 if the request should not be allowed
 */

alias ssh_service_request_callback = int function(ssh_session session, const(char)* service, void *userdata);

/**
 * @brief Handles an SSH new channel open session request
 * @param session current session handler
 * @param userdata Userdata to be passed to the callback function.
 * @returns a valid ssh_channel handle if the request is to be allowed
 * @returns NULL if the request should not be allowed
 * @warning The channel pointer returned by this callback must be closed by the application.
 */
alias ssh_channel_open_request_session_callback = ssh_channel function(ssh_session session, void *userdata);

/*
 * @brief handle the beginning of a GSSAPI authentication, server side.
 * @param session current session handler
 * @param user the username of the client
 * @param n_oid number of available oids
 * @param oids OIDs provided by the client
 * @returns an ssh_string containing the chosen OID, that's supported by both
 * client and server.
 * @warning It is not necessary to fill this callback in if libssh is linked
 * with libgssapi.
 */
alias ssh_gssapi_select_oid_callback = ssh_string function(ssh_session session, const(char)* user,
		int n_oid, ssh_string *oids, void *userdata);

/*
 * @brief handle the negociation of a security context, server side.
 * @param session current session handler
 * @param[in] input_token input token provided by client
 * @param[out] output_token output of the gssapi accept_sec_context method,
 * 				NULL after completion.
 * @returns SSH_OK if the token was generated correctly or accept_sec_context
 * returned GSS_S_COMPLETE
 * @returns SSH_ERROR in case of error
 * @warning It is not necessary to fill this callback in if libssh is linked
 * with libgssapi.
 */
alias ssh_gssapi_accept_sec_ctx_callback = int function(ssh_session session,
		ssh_string input_token, ssh_string *output_token, void *userdata);

/*
 * @brief Verify and authenticates a MIC, server side.
 * @param session current session handler
 * @param[in] mic input mic to be verified provided by client
 * @param[in] mic_buffer buffer of data to be signed.
 * @param[in] mic_buffer_size size of mic_buffer
 * @returns SSH_OK if the MIC was authenticated correctly
 * @returns SSH_ERROR in case of error
 * @warning It is not necessary to fill this callback in if libssh is linked
 * with libgssapi.
 */
alias ssh_gssapi_verify_mic_callback = int function(ssh_session session,
		ssh_string mic, void *mic_buffer, size_t mic_buffer_size, void *userdata);

enum SSH_SOCKET_FLOW_WRITEWILLBLOCK = 1;
enum SSH_SOCKET_FLOW_WRITEWONTBLOCK = 2;

enum SSH_SOCKET_EXCEPTION_EOF = 1;
enum SSH_SOCKET_EXCEPTION_ERROR = 2;

enum SSH_SOCKET_CONNECTED_OK = 1;
enum SSH_SOCKET_CONNECTED_ERROR = 2;
enum SSH_SOCKET_CONNECTED_TIMEOUT = 3;

/**
 * @brief Initializes an ssh_callbacks_struct
 * A call to this macro is mandatory when you have set a new
 * ssh_callback_struct structure. Its goal is to maintain the binary
 * compatibility with future versions of libssh as the structure
 * evolves with time.
 */
void ssh_callbacks_init(ssh_callbacks p) {
	p.size= ((*(p)).sizeof);
}

/**
 * @internal
 * @brief tests if a callback can be called without crash
 *  verifies that the struct size if big enough
 *  verifies that the callback pointer exists
 * @param p callback pointer
 * @param c callback name
 * @returns nonzero if callback can be called
 */
bool ssh_callbacks_exists(P,C)(P p,C c) {
	return (p != null) && ( cast(char*)&(p.c) < cast(char*)(p) + (p).size ) && (p.c != null);
}

/** @brief Prototype for a packet callback, to be called when a new packet arrives
 * @param session The current session of the packet
 * @param type packet type (see ssh2.h)
 * @param packet buffer containing the packet, excluding size, type and padding fields
 * @param user user argument to the callback
 * and are called each time a packet shows up
 * @returns SSH_PACKET_USED Packet was parsed and used
 * @returns SSH_PACKET_NOT_USED Packet was not used or understood, processing must continue
 */
alias ssh_packet_callback = int function(ssh_session session, ubyte type, ssh_buffer packet, void *user);

/** return values for a ssh_packet_callback */
/** Packet was used and should not be parsed by another callback */
enum SSH_PACKET_USED = 1;
/** Packet was not used and should be passed to any other callback
 * available */
enum SSH_PACKET_NOT_USED = 2;


/** @brief This macro declares a packet callback handler
 * @code
 * SSH_PACKET_CALLBACK(mycallback){
 * ...
 * }
 * @endcode
 */
// TODO: This macro might be a dead end in D.  We can make the function decl
//       with a mixin template, but the body will be absent.  Hmmm.
//mixin template SSH_PACKET_CALLBACK(string name)
//{
//	mixin("int "~name~" (ssh_session session, ubyte type, ssh_buffer packet, void *user);");
//}

alias ssh_packet_callbacks = ssh_packet_callbacks_struct*;

/**
 * @brief SSH channel data callback. Called when data is available on a channel
 * @param session Current session handler
 * @param channel the actual channel
 * @param data the data that has been read on the channel
 * @param len the length of the data
 * @param is_stderr is 0 for stdout or 1 for stderr
 * @param userdata Userdata to be passed to the callback function.
 * @returns number of bytes processed by the callee. The remaining bytes will
 * be sent in the next callback message, when more data is available.
 */
alias ssh_channel_data_callback = int function(ssh_session session,
                                           ssh_channel channel,
                                           void *data,
                                           uint len,
                                           int is_stderr,
                                           void *userdata);

/**
 * @brief SSH channel eof callback. Called when a channel receives EOF
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
alias ssh_channel_eof_callback = void function(ssh_session session,
                                           ssh_channel channel,
                                           void *userdata);

/**
 * @brief SSH channel close callback. Called when a channel is closed by remote peer
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
alias ssh_channel_close_callback = void function(ssh_session session,
                                            ssh_channel channel,
                                            void *userdata);

/**
 * @brief SSH channel signal callback. Called when a channel has received a signal
 * @param session Current session handler
 * @param channel the actual channel
 * @param signal the signal name (without the SIG prefix)
 * @param userdata Userdata to be passed to the callback function.
 */
alias ssh_channel_signal_callback = void function(ssh_session session,
                                            ssh_channel channel,
                                            const(char)* signal,
                                            void *userdata);

/**
 * @brief SSH channel exit status callback. Called when a channel has received an exit status
 * @param session Current session handler
 * @param channel the actual channel
 * @param userdata Userdata to be passed to the callback function.
 */
alias ssh_channel_exit_status_callback = void function(ssh_session session,
                                            ssh_channel channel,
                                            int exit_status,
                                            void *userdata);

/**
 * @brief SSH channel exit signal callback. Called when a channel has received an exit signal
 * @param session Current session handler
 * @param channel the actual channel
 * @param signal the signal name (without the SIG prefix)
 * @param core a boolean telling wether a core has been dumped or not
 * @param errmsg the description of the exception
 * @param lang the language of the description (format: RFC 3066)
 * @param userdata Userdata to be passed to the callback function.
 */
alias ssh_channel_exit_signal_callback = void function(ssh_session session,
                                            ssh_channel channel,
                                            const(char)* signal,
                                            int core,
                                            const(char)* errmsg,
                                            const(char)* lang,
                                            void *userdata);

/**
 * @brief SSH channel PTY request from a client.
 * @param channel the channel
 * @param term The type of terminal emulation
 * @param width width of the terminal, in characters
 * @param height height of the terminal, in characters
 * @param pxwidth width of the terminal, in pixels
 * @param pxheight height of the terminal, in pixels
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the pty request is accepted
 * @returns -1 if the request is denied
 */
alias ssh_channel_pty_request_callback = int function(ssh_session session,
                                            ssh_channel channel,
                                            const(char)* term,
                                            int width, int height,
                                            int pxwidth, int pwheight,
                                            void *userdata);

/**
 * @brief SSH channel Shell request from a client.
 * @param channel the channel
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the shell request is accepted
 * @returns 1 if the request is denied
 */
alias ssh_channel_shell_request_callback = int function(ssh_session session,
                                            ssh_channel channel,
                                            void *userdata);
/**
 * @brief SSH auth-agent-request from the client. This request is
 * sent by a client when agent forwarding is available.
 * Server is free to ignore this callback, no answer is expected.
 * @param channel the channel
 * @param userdata Userdata to be passed to the callback function.
 */
alias ssh_channel_auth_agent_req_callback = void function(ssh_session session,
                                            ssh_channel channel,
                                            void *userdata);

/**
 * @brief SSH X11 request from the client. This request is
 * sent by a client when X11 forwarding is requested(and available).
 * Server is free to ignore this callback, no answer is expected.
 * @param channel the channel
 * @param userdata Userdata to be passed to the callback function.
 */
alias ssh_channel_x11_req_callback = void function(ssh_session session,
                                            ssh_channel channel,
                                            int single_connection,
                                            const(char)* auth_protocol,
                                            const(char)* auth_cookie,
                                            uint screen_number,
                                            void *userdata);
/**
 * @brief SSH channel PTY windows change (terminal size) from a client.
 * @param channel the channel
 * @param width width of the terminal, in characters
 * @param height height of the terminal, in characters
 * @param pxwidth width of the terminal, in pixels
 * @param pxheight height of the terminal, in pixels
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the pty request is accepted
 * @returns -1 if the request is denied
 */
alias ssh_channel_pty_window_change_callback = int function(ssh_session session,
                                            ssh_channel channel,
                                            int width, int height,
                                            int pxwidth, int pwheight,
                                            void *userdata);

/**
 * @brief SSH channel Exec request from a client.
 * @param channel the channel
 * @param command the shell command to be executed
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the exec request is accepted
 * @returns 1 if the request is denied
 */
alias ssh_channel_exec_request_callback = int function(ssh_session session,
                                            ssh_channel channel,
                                            const(char)* command,
                                            void *userdata);

/**
 * @brief SSH channel environment request from a client.
 * @param channel the channel
 * @param env_name name of the environment value to be set
 * @param env_value value of the environment value to be set
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the env request is accepted
 * @returns 1 if the request is denied
 * @warning some environment variables can be dangerous if changed (e.g.
 * 			LD_PRELOAD) and should not be fulfilled.
 */
alias ssh_channel_env_request_callback = int function(ssh_session session,
                                            ssh_channel channel,
                                            const(char)* env_name,
                                            const(char)* env_value,
                                            void *userdata);
/**
 * @brief SSH channel subsystem request from a client.
 * @param channel the channel
 * @param subsystem the subsystem required
 * @param userdata Userdata to be passed to the callback function.
 * @returns 0 if the subsystem request is accepted
 * @returns 1 if the request is denied
 */
alias ssh_channel_subsystem_request_callback = int function(ssh_session session,
                                            ssh_channel channel,
                                            const(char)* subsystem,
                                            void *userdata);


/** @} */

/** @group libssh_threads
 * @{
 */

alias ssh_thread_callback = int function(void **lock);

alias ssh_thread_id_callback = c_ulong function();

// For functions/structs.
extern (C) nothrow @nogc:

/**
 * @brief Set the thread callbacks structure.
 *
 * This is necessary if your program is using libssh in a multithreaded fashion.
 * This function must be called first, outside of any threading context (in your
 * main() function for instance), before you call ssh_init().
 *
 * @param[in] cb   A pointer to a ssh_threads_callbacks_struct structure, which
 *                 contains the different callbacks to be set.
 *
 * @returns        Always returns SSH_OK.
 *
 * @see ssh_threads_callbacks_struct
 * @see SSH_THREADS_PTHREAD
 * @bug libgcrypt 1.6 and bigger backend does not support custom callback.
 *      Using anything else than pthreads here will fail.
 */
int ssh_threads_set_callbacks(ssh_threads_callbacks_struct *cb);

/**
 * @brief returns a pointer on the pthread threads callbacks, to be used with
 * ssh_threads_set_callbacks.
 * @warning you have to link with the library ssh_threads.
 * @see ssh_threads_set_callbacks
 */
ssh_threads_callbacks_struct* ssh_threads_get_pthread();

/**
 * @brief Get the noop threads callbacks structure
 *
 * This can be used with ssh_threads_set_callbacks. These callbacks do nothing
 * and are being used by default.
 *
 * @return Always returns a valid pointer to the noop callbacks structure.
 *
 * @see ssh_threads_set_callbacks
 */
ssh_threads_callbacks_struct* ssh_threads_get_noop();

/**
 * @brief Set the logging callback function.
 *
 * @param[in]  cb  The callback to set.
 *
 * @return         0 on success, < 0 on errror.
 */
int ssh_set_log_callback(ssh_logging_callback cb);

/**
 * @brief Get the pointer to the logging callback function.
 *
 * @return The pointer the the callback or NULL if none set.
 */
ssh_logging_callback ssh_get_log_callback();

/**
 * The structure to replace libssh functions with appropriate callbacks.
 */
struct ssh_callbacks_struct {
  /** DON'T SET THIS use ssh_callbacks_init() instead. */
  size_t size;
  /**
   * User-provided data. User is free to set anything he wants here
   */
  void *userdata;
  /**
   * This functions will be called if e.g. a keyphrase is needed.
   */
  ssh_auth_callback auth_function;
  /**
   * This function will be called each time a loggable event happens.
   */
  ssh_log_callback log_function;
  /**
   * This function gets called during connection time to indicate the
   * percentage of connection steps completed.
   */
  void function(void *userdata, float status) connect_status_function;
  /**
   * This function will be called each time a global request is received.
   */
  ssh_global_request_callback global_request_function;
  /** This function will be called when an incoming X11 request is received.
   */
  ssh_channel_open_request_x11_callback channel_open_request_x11_function;
}

alias ssh_callbacks = ssh_callbacks_struct*;


/**
 * This structure can be used to implement a libssh server, with appropriate callbacks.
 */

struct ssh_server_callbacks_struct {
  /** DON'T SET THIS use ssh_callbacks_init() instead. */
  size_t size;
  /**
   * User-provided data. User is free to set anything he wants here
   */
  void *userdata;
  /** This function gets called when a client tries to authenticate through
   * password method.
   */
  ssh_auth_password_callback auth_password_function;

  /** This function gets called when a client tries to authenticate through
   * none method.
   */
  ssh_auth_none_callback auth_none_function;

  /** This function gets called when a client tries to authenticate through
   * gssapi-mic method.
   */
  ssh_auth_gssapi_mic_callback auth_gssapi_mic_function;

  /** this function gets called when a client tries to authenticate or offer
   * a public key.
   */
  ssh_auth_pubkey_callback auth_pubkey_function;

  /** This functions gets called when a service request is issued by the
   * client
   */
  ssh_service_request_callback service_request_function;
  /** This functions gets called when a new channel request is issued by
   * the client
   */
  ssh_channel_open_request_session_callback channel_open_request_session_function;
  /** This function will be called when a new gssapi authentication is attempted.
   */
  ssh_gssapi_select_oid_callback gssapi_select_oid_function;
  /** This function will be called when a gssapi token comes in.
   */
  ssh_gssapi_accept_sec_ctx_callback gssapi_accept_sec_ctx_function;
  /* This function will be called when a MIC needs to be verified.
   */
  ssh_gssapi_verify_mic_callback gssapi_verify_mic_function;
}

alias ssh_server_callbacks = ssh_server_callbacks_struct*;



/**
 * These are the callbacks exported by the socket structure
 * They are called by the socket module when a socket event appears
 */
struct ssh_socket_callbacks_struct {
  /**
   * User-provided data. User is free to set anything he wants here
   */
  void *userdata;
	/**
	 * This function will be called each time data appears on socket. The data
	 * not consumed will appear on the next data event.
	 */
  ssh_callback_data data;
  /** This function will be called each time a controlflow state changes, i.e.
   * the socket is available for reading or writing.
   */
  ssh_callback_int controlflow;
  /** This function will be called each time an exception appears on socket. An
   * exception can be a socket problem (timeout, ...) or an end-of-file.
   */
  ssh_callback_int_int exception;
  /** This function is called when the ssh_socket_connect was used on the socket
   * on nonblocking state, and the connection successed.
   */
  ssh_callback_int_int connected;
}

alias ssh_socket_callbacks = ssh_socket_callbacks_struct*;

struct ssh_channel_callbacks_struct {
  /** DON'T SET THIS use ssh_callbacks_init() instead. */
  size_t size;
  /**
   * User-provided data. User is free to set anything he wants here
   */
  void *userdata;
  /**
   * This functions will be called when there is data available.
   */
  ssh_channel_data_callback channel_data_function;
  /**
   * This functions will be called when the channel has received an EOF.
   */
  ssh_channel_eof_callback channel_eof_function;
  /**
   * This functions will be called when the channel has been closed by remote
   */
  ssh_channel_close_callback channel_close_function;
  /**
   * This functions will be called when a signal has been received
   */
  ssh_channel_signal_callback channel_signal_function;
  /**
   * This functions will be called when an exit status has been received
   */
  ssh_channel_exit_status_callback channel_exit_status_function;
  /**
   * This functions will be called when an exit signal has been received
   */
  ssh_channel_exit_signal_callback channel_exit_signal_function;
  /**
   * This function will be called when a client requests a PTY
   */
  ssh_channel_pty_request_callback channel_pty_request_function;
  /**
   * This function will be called when a client requests a shell
   */
  ssh_channel_shell_request_callback channel_shell_request_function;
  /** This function will be called when a client requests agent
   * authentication forwarding.
   */
  ssh_channel_auth_agent_req_callback channel_auth_agent_req_function;
  /** This function will be called when a client requests X11
   * forwarding.
   */
  ssh_channel_x11_req_callback channel_x11_req_function;
  /** This function will be called when a client requests a
   * window change.
   */
  ssh_channel_pty_window_change_callback channel_pty_window_change_function;
  /** This function will be called when a client requests a
   * command execution.
   */
  ssh_channel_exec_request_callback channel_exec_request_function;
  /** This function will be called when a client requests an environment
   * variable to be set.
   */
  ssh_channel_env_request_callback channel_env_request_function;
  /** This function will be called when a client requests a subsystem
   * (like sftp).
   */
  ssh_channel_subsystem_request_callback channel_subsystem_request_function;
}

alias ssh_channel_callbacks = ssh_channel_callbacks_struct*;


struct ssh_threads_callbacks_struct {
	const(char)* type;
	ssh_thread_callback mutex_init;
	ssh_thread_callback mutex_destroy;
	ssh_thread_callback mutex_lock;
	ssh_thread_callback mutex_unlock;
	ssh_thread_id_callback thread_id;
}

struct ssh_packet_callbacks_struct {
	/** Index of the first packet type being handled */
	ubyte start;
	/** Number of packets being handled by this callback struct */
	ubyte n_callbacks;
	/** A pointer to n_callbacks packet callbacks */
	ssh_packet_callback *callbacks;
  /**
   * User-provided data. User is free to set anything he wants here
   */
	void *user;
}

/**
 * @brief Set the session callback functions.
 *
 * This functions sets the callback structure to use your own callback
 * functions for auth, logging and status.
 *
 * @code
 * struct ssh_callbacks_struct cb = {
 *   .userdata = data,
 *   .auth_function = my_auth_function
 * };
 * ssh_callbacks_init(&cb);
 * ssh_set_callbacks(session, &cb);
 * @endcode
 *
 * @param  session      The session to set the callback structure.
 *
 * @param  cb           The callback structure itself.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 */
int ssh_set_callbacks(ssh_session session, ssh_callbacks cb);

/**
 * @brief Set the session server callback functions.
 *
 * This functions sets the callback structure to use your own callback
 * functions for user authentication, new channels and requests.
 *
 * @code
 * struct ssh_server_callbacks_struct cb = {
 *   .userdata = data,
 *   .auth_password_function = my_auth_function
 * };
 * ssh_callbacks_init(&cb);
 * ssh_set_server_callbacks(session, &cb);
 * @endcode
 *
 * @param  session      The session to set the callback structure.
 *
 * @param  cb           The callback structure itself.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 */
int ssh_set_server_callbacks(ssh_session session, ssh_server_callbacks cb);


/**
 * @brief Set the channel callback functions.
 *
 * This functions sets the callback structure to use your own callback
 * functions for channel data and exceptions
 *
 * @code
 * struct ssh_channel_callbacks_struct cb = {
 *   .userdata = data,
 *   .channel_data = my_channel_data_function
 * };
 * ssh_callbacks_init(&cb);
 * ssh_set_channel_callbacks(channel, &cb);
 * @endcode
 *
 * @param  channel      The channel to set the callback structure.
 *
 * @param  cb           The callback structure itself.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 */
int ssh_set_channel_callbacks(ssh_channel channel,
                                         ssh_channel_callbacks cb);

/* @} */
