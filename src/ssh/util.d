module ssh.util;

import std.stdio;

import core.stdc.errno;

import c.libssh.libssh;
import c.libssh.callbacks;

static this()
{
	int rc = ssh_init();
	if ( rc != 0 )
		throw new Exception("Could not initialize SSH library.  Call to ssh_init() failed.");
}

static ~this()
{
	int rc = ssh_finalize();
	if ( rc != 0 )
		stderr.writeln("Cleanup failure: Could not finalize SSH library.  Call to ssh_finalize() failed.");
}

class SshException : Exception
{
	public static SshException errorCalling(ssh_session session, string sshFunctionCalled,
		string file = __FILE__, size_t line = __LINE__)
	{
		string msg =
			"Error: Call to "~sshFunctionCalled~" failed: \n";

		return new SshException(session, msg, file, line);
	}

	public static void warningCalling(ssh_session session, string sshFunctionCalled,
		string file = __FILE__, size_t line = __LINE__)
	{
		import std.stdio;
		stderr.writeln("Warning: Call to "~sshFunctionCalled~" failed: \n");
		stderr.writeln(getSshError(session));
	}

	this(ssh_session session, string msg, string file = __FILE__, size_t line = __LINE__)
	{
		super(msg ~ getSshError(session), file, line);
	}

	private static string getSshError(ssh_session session)
	{
		import std.string : fromStringz;
		import std.exception : assumeUnique;
		return ssh_get_error(session).fromStringz().assumeUnique();
	}
}

struct SshSessionForRemotely
{
	public ssh_session           session;
	public ssh_callbacks_struct  callbacks;
	public ssh_channel           x11Channel;
}

/// Uses std.stdio's stdin and stdout streams to ask the user for a yes/no
/// response.  It accepts case-insensitive input as well as y/n instead of
/// yes/no.
/// Throws an exception if readln() throws an exception.
/// returns:
///   true if the user entered "y" or "yes"
///   false if the user entered "n" or "no"
bool cliReadYesNo()
{
	import std.uni;
	while(true)
	{
		string response = null;
		response = std.uni.toLower(readln());

		if ( response == "yes" || response == "y" )
			return true;
		else
		if ( response == "no"  || response == "n" )
			return false;
		else
		{
			stderr.writeln("Response not understood.");
			stderr.writeln(`Please type "yes" or "no".`);
		}
	}
}

string toColonSeparatedHash(const ubyte[] hash)
{
	import core.stdc.stdlib;
	import std.string;
	char* str = ssh_get_hexa(hash.ptr, hash.length);
	// The example code used free().
	//    (from: http://api.libssh.org/master/libssh_tutor_guided_tour.html)
	// The API docs mention ssh_string_free_char().
	//    (from: http://api.libssh.org/master/group__libssh__session.html#ga6ebcfc53884fdc5afb1607c94f8007d4)
	// How am I supposed to free this?
	scope(exit) ssh_string_free_char(str);
	return str.fromStringz().idup;
}

// Modified from example at
//   http://api.libssh.org/master/libssh_tutor_guided_tour.html
bool cliVerifyKnownhost(ssh_session session)
{
	import std.stdio;
	import core.stdc.stdlib;
	import core.stdc.string : strerror;
	int state, rc;
	ubyte* hashPtr = null;
	size_t hashLen = 0;
	state = ssh_is_server_known(session);
	if ( state == ssh_server_known_e.SSH_SERVER_ERROR )
		throw SshException.errorCalling(session, "ssh_is_server_known");

	ssh_key key;
	rc = ssh_get_publickey(session, &key);
	if ( rc != SSH_OK )
		throw SshException.errorCalling(session, "ssh_get_publickey");
	scope(exit)
		ssh_key_free(key);

	rc = ssh_get_publickey_hash(
		key, ssh_publickey_hash_type.SSH_PUBLICKEY_HASH_SHA1, &hashPtr, &hashLen);
	// Author's note: I expected to compare against SSH_OK, but it seems like 0 is the reference here.
	// (source: http://api.libssh.org/master/group__libssh__session.html#ga7a7b16a4bed6d8d58f10bdb269172ff7)
	if ( rc != 0 )
		throw SshException.errorCalling(session, "ssh_get_publickey_hash");
	scope(exit)
		free(hashPtr);

	ubyte[] hash = hashPtr[0..hashLen];

	final switch (state)
	{
		case ssh_server_known_e.SSH_SERVER_KNOWN_OK:
			break; /* ok */
		case ssh_server_known_e.SSH_SERVER_KNOWN_CHANGED:
			stderr.writeln ("Host key for server changed: it is now:");
			stderr.writefln("Public key hash %s", toColonSeparatedHash(hash));
			stderr.writeln ("For security reasons, connection will be stopped");
			return false;
		case ssh_server_known_e.SSH_SERVER_FOUND_OTHER:
			stderr.writeln ("The host key for this server was not found but an other"~
				"type of key exists.");
			stderr.writeln ("An attacker might change the default server key to"~
				"confuse your client into thinking the key does not exist");
			return false;
		case ssh_server_known_e.SSH_SERVER_FILE_NOT_FOUND:
			stderr.writeln ("Could not find known host file.");
			stderr.writeln ("If you accept the host key here, the file will be"~
				"automatically created.");
			/* fallback to SSH_SERVER_NOT_KNOWN behavior */
		case ssh_server_known_e.SSH_SERVER_NOT_KNOWN:
			while(true)
			{
				try
				{
					stderr.writeln ("The server is unknown. Do you trust the host key?");
					stderr.writeln ("Public key hash: %s", toColonSeparatedHash(hash));
					if( cliReadYesNo() == false )
						return false;
					break;
				}
				catch( Exception e )
				{
					stderr.writeln("");
					stderr.writefln("Error: %s", e);
					continue;
				}
				assert(0);
			}

			if (ssh_write_knownhost(session) < 0)
				throw SshException.errorCalling(session, "ssh_write_knownhost");
			//{
				//stderr.writefln("Error: %s\n", strerror(errno));
				//return false;
			//}
			break;
		case ssh_server_known_e.SSH_SERVER_ERROR:
			throw SshException.errorCalling(session, "ssh_is_server_known");
	}
	return true;
}

nothrow ssh_channel openX11ChannelCallback(
	ssh_session session, const(char)*originator_address, int originator_port, void *userdata)
{
	import core.time;
	import core.thread;
	try
	{
		int rc;
		auto sessionObj = cast(SshSessionForRemotely*)userdata;

		// Allocate the channel.
		ssh_channel channel = ssh_channel_new(session);
		if (channel == null)
			throw SshException.errorCalling(session, "ssh_channel_new");
		scope(failure)
			ssh_channel_free(channel);

		// Open the channel.
		while(true)
		{
			rc = ssh_channel_open_x11(channel, originator_address, originator_port);
			if ( rc == SSH_OK )
				break;
			else
			if ( rc == SSH_AGAIN )
			{
				Thread.sleep( dur!("msecs")( 50 ) ); // sleep for 50 milliseconds
				continue;
			}
			else
			if ( rc == SSH_ERROR )
				throw SshException.errorCalling(session, "ssh_channel_open_x11");
			else
				assert(0);
		}
		scope(failure)
			ssh_channel_close(channel);

		// Keep track of the channel, so we can free/close it later.
		sessionObj.x11Channel = channel;

		return channel;
	}
	catch ( Exception e )
	{
		try
			stderr.writeln(e.toString());
		catch ( Exception e2 )
			{} // Cry more?
		return null;
	}
}

/// Caller is responsible for calling cliEndSshSession after calling this.
SshSessionForRemotely* cliStartSshSession(string host, string user, SecureMem!(char[]) password)
{
	import std.string : toStringz, fromStringz, format;
	import std.exception : assumeUnique;
	import std.array;

	SshSessionForRemotely* sessionObj = new SshSessionForRemotely();
	int rc;
	// Open session and set options
	ssh_session session = ssh_new();
	if (session == null)
		throw new Exception("ssh_new() failed."); // Hopefully this never happens to anyone. orz
	scope(failure)
		ssh_free(session);
	sessionObj.session = session;

	ssh_options_set(session, ssh_options_e.SSH_OPTIONS_HOST, host.toStringz());
	ssh_options_set(session, ssh_options_e.SSH_OPTIONS_USER, host.toStringz());

	ssh_callbacks_init(&sessionObj.callbacks);
	sessionObj.callbacks.channel_open_request_x11_function = &openX11ChannelCallback;
	sessionObj.callbacks.userdata = cast(void*)sessionObj;
	ssh_set_callbacks(session, &sessionObj.callbacks);

	// Connect to server
	rc = ssh_connect(session);
	if (rc != SSH_OK)
		throw new SshException(session, format("Error connecting to %s: \n", host));
	scope(failure)
		ssh_disconnect(session);

	// Verify the server's identity
	// For the source code of verify_knowhost(), check previous example
	if (cliVerifyKnownhost(session) < 0)
		throw new Exception("Could not verify host's identity.");

	// Authenticate ourselves
	// TODO: This needs to be way better.  We should do all of the proper
	//   negotiation, including having the server list auth methods and then
	//   trying them while listening to the server's demands.  And most
	//   importantly, this will allow public key authentication.
	auto passwordChosen = password;
	if ( password == null || password.empty )
		passwordChosen = cliGetPassword("Password: ");
	scope(exit)
	{
		if ( passwordChosen !is password )
			secureFree(cast(void[])passwordChosen);
	}

	rc = ssh_userauth_password(session, null, passwordChosen.ptr);
	if (rc != ssh_auth_e.SSH_AUTH_SUCCESS)
		throw new SshException(session, format("Error authenticating with password: \n"));

	sessionObj.x11Channel = null;
	return sessionObj;
}

/// See cliStartSshSession()
void cliEndSshSession(SshSessionForRemotely* sessionObj)
{
	ssh_session session = sessionObj.session;
	int rc;
	if ( sessionObj.x11Channel !is null )
	{
		if ( ssh_channel_is_open(sessionObj.x11Channel) )
		{
			rc = ssh_channel_close(sessionObj.x11Channel);
			if (rc != SSH_OK)
				SshException.warningCalling(session, "ssh_channel_close");
		}
		ssh_channel_free(sessionObj.x11Channel);
	}

	ssh_disconnect(session);
	ssh_free(session);

	sessionObj.session = null;
	sessionObj.x11Channel = null;
}

import security;
// The linux "getpass" function is supposedly obsolete, so this is the
// alternative.  Thanks goes out to "dfa" in the following post:
//   http://stackoverflow.com/questions/1196418/getting-a-password-in-c-without-using-getpass-3
// That answer made it suck a lot less to solve this silly problem.
// This also allows us to control how the memory is allocated for the password
// (security!), and although the original "getpass" function had a manpage,
// it never explained just how the returned string was supposed to be freed.
/// The caller is responsible for calling secureFree(...) on the returned
/// password string.
/// The returned password is guaranteed to be null-terminated and its pointer
/// may be passed directly into C functions without calling toStringz() on it.
SecureMem!(char[]) cliGetPassword(string prompt)
{
	import core.sys.posix.termios;
	import core.stdc.string : strerror;
	import core.stdc.stdio;
	import core.stdc.stdlib;
	import posix;
	termios oflags;
	termios nflags;
	SecureMem!(char[]) passwordBuf = security.secureMalloc(512);

	/* disabling echo */
	if ( tcgetattr(fileno(stdin), &oflags) != 0 )
		throw PosixException.whenCalling("tcgetattr", errno);
	nflags = oflags;
	nflags.c_lflag &= ~ECHO;
	nflags.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0)
		throw PosixException.whenCalling("tcsetattr", errno);

	writeln(prompt);
	size_t len = readln(passwordBuf.data);
	passwordBuf[len-1] = '\0'; // Replace the terminator char (\n) with a null terminator (\0).
	auto password = passwordBuf[0..len-1]; // -1 to keep the null terminator out of the slice.
	//writefln("THIS IS THE PASSWORD EVERYONE LOOK O.O -> '%s'", password);

	/* restore terminal */
	if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0)
		throw PosixException.whenCalling("tcsetattr", errno);

	return password;
}

ssh_channel startNoninteractiveShell(SshSessionForRemotely* sessionObj)
{
	ssh_session session = sessionObj.session;
	ssh_channel channel;
	int rc;
	channel = ssh_channel_new(session);
	if (channel == null)
		throw SshException.errorCalling(session, "ssh_channel_new");
	scope(failure)
		ssh_channel_free(channel);

	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK)
		throw SshException.errorCalling(session, "ssh_channel_open_session");
	scope(failure)
	{
		ssh_channel_close(channel);
	}

	rc = ssh_channel_request_x11(channel, 1, null, null, 0);
	if (rc != SSH_OK)
		SshException.warningCalling(session, "ssh_channel_request_x11");

	rc = ssh_channel_request_shell(channel);
	if (rc != SSH_OK)
		throw SshException.errorCalling(session, "ssh_channel_request_shell");

	return channel;
}

void endNoninteractiveShell(ssh_channel channel)
{
	int rc;
	ssh_session session = ssh_channel_get_session(channel);
	rc = ssh_channel_close(channel);
	//ssh_channel_send_eof(channel);
	ssh_channel_free(channel);
	if ( rc != SSH_OK )
		throw SshException.errorCalling(session, "ssh_channel_close");
}