module remotely;

string usage =
`Usage: remotely --worker-hostname=<host> [<options>] -- <command> [<args> ...]

The remotely program allows the given <command> to be executed using the CPU
resources of another machine, while still behaving as if it were being
executed locally.

This is similar to process migration: a local program using local data is
executed as a process on another machine.  However, this program differs from
other process migration methodologies in several ways:
`~` - It has very few dependencies.  Both machines involved must have SSH available
`~`     and be running SSH daemons.
`~` - It requires no setup in advance.  Existing systems can use this tool to start
`~`     processes on other existing systems.  It does not require kernel modules,
`~`     special filesystems, or any such mechanisms be installed before work can
`~`     proceed.
`~` - It cannot migrate existing processes.  The user must know which machine
`~`     they want to run their process on when they start executing it.
`~` - It is binary in nature, and cannot be used to extract CPU resources from
`~`     multiple machines.  Of course, if the worker machine is a virtualized system,
`~`     then this tool makes it possible for a non-virtualized system to take
`~`     advantage of any number of physical machines that might pool resources for
`~`     the virtualized system.
`~` - Security-wise, the overseer machine must trust the worker machine.

Security considerations:
The worker machine will be able to view/edit the overseer machine, because it is
necessary for the overseer to share its local file system with the permissions
available to the overseer's user.  This will not allow other users on the worker
machine to access the share, but the root account (system admin) on the worker
machine could conceivably access the share inspite of any security measures
because they could modify the SSH binary on the worker machine to give
themselves access to the share.

If it is necessary to send a password to the worker machine, place the password
in the REMOTELY_WORKER_PASSWORD environment variable.  remotely provides no
command line parameter for this password because command arguments appear in
process enumerations on a system (ex: whenever someone runs "ps aux" or "top").
Placing a password into an argument would allow other users on the system to
easily learn the password.  It is recommended to establish public-private
key authentication with the worker machine before using remotely, as it is
more secure and works automatically.

The overseer machine will authenticate the worker machine with public-private
key authentication using a temporary key pair generated on a per-execution
basis.

Options:`;
/+
`~`    --overseer-hostname=<host> The hostname or external IP address of the
`~`                               local machine that is requesting CPU time from
`~`                               the worker machine.  This must be the hostname/
`~`                               address as seen from the worker machine; so
`~`                               adjust this needed when the overseer is behind
`~`                               a firewall or subnet.
`~`                               By default, this will be set to the hostname
`~`                               returned by the system's gethostname() function.
`~`
`~`    --overseer-address=<addr>  Does the same thing as --overseer-hostname.
`~`
`~`    --overseer-username=<user> The username that the worker machine is to use
`~`                               when authenticating itself to the overseer
`~`                               machine.  By default, this is the current
`~`                               user name.
`~`
`~`    --worker-hostname=<host>   The hostname of IP address of the machine that
`~`                               is to perform the computation.
`~`                               This parameter is required.
`~`
`~`    --worker-address=<addr>    Does the same thing as --worker-hostname.
`~`
`~`    --worker-username=<user>   The username that is used when the overseer
`~`                               authenticates itself to the worker.
`~`                               By default, this is the guest account.
`;+/


//
// Terminology:
//
// Terms like "local" or "remote" are avoided in variable names here because
// their intuitive meaning changes depending on which machine is executing a
// command.  This makes such relative terms confusing for a program like this.
// Instead, an attempt will be made to use terms that are unambiguous throughout
// the execution of this program.
//
// "Overseer" refers to the machine or user that is executing this program as
//   a way to invoke another program using another machine's CPU resources.
//   In short: the "overseer" is borrowing CPU resources from the "worker".
//
// "Worker" refers to the machine that will execute the program specified in an
//   argument to this program.

import core.sys.posix.netinet.in_;
import core.sys.posix.sys.socket;
import core.sys.posix.sys.types;
import core.sys.posix.unistd;
import core.sys.posix.pwd;
import core.stdc.errno;
import core.stdc.string;
//import core.stdc.stdio;

import c.net.if_;
import c.libssh.libssh;
import c.ifaddrs;

import std.array;
import std.conv;
import std.exception : assumeUnique;
import std.getopt;
import std.process;
import std.random;
import std.stdio;
import std.string : fromStringz, toStringz;

import ssh.util;
import posix;
import security;

string getDefaultIpAddr()
{
	ifaddrs* listStart = null;
	ifaddrs* iface;
	if (getifaddrs(&listStart) == -1)
		throw PosixException.whenCalling("getifaddrs", errno);
	scope(exit) freeifaddrs(listStart);

	char[256] addrBuf = void;
	addrBuf[0] = '\0';
	const(char)* result = addrBuf.ptr;

	iface = listStart;
	for(; iface != null; iface = iface.ifa_next)
	{
		// Filter out interfaces that are down, lack addresses, are loopbacks,
		// or implement the wrong protocol (non-IP).
		if ( !iface.ifa_addr ) continue;
		if ( (iface.ifa_flags & IFF_UP) == 0 ) continue;
		if ( (iface.ifa_flags & IFF_LOOPBACK) != 0 ) continue;
		if ( iface.ifa_addr.sa_family != AF_INET && iface.ifa_addr.sa_family != AF_INET6)
			continue;

		// We found one!  Stringize it.
		if (iface.ifa_addr.sa_family == AF_INET) {
			auto addrIn = cast(sockaddr_in*) iface.ifa_addr;
			result = inet_ntop(AF_INET, &addrIn.sin_addr, addrBuf.ptr, addrBuf.length);
		} else { // AF_INET6
			auto addrIn6 = cast(sockaddr_in6*) iface.ifa_addr;
			result = inet_ntop(AF_INET6, &addrIn6.sin6_addr, addrBuf.ptr, addrBuf.length);
		}

		if ( result == null )
			throw PosixException.whenCalling("inet_ntop", errno);
		break;
	}

	return result.fromStringz().idup;
}


int main(string[] args)
{
	// =====================================================================
	//                  ----- Initialize LibreSSL -----
	// =====================================================================
	//initSecureHeap();

	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	// =====================================================================
	//              ----- Parse command line arguments -----
	// =====================================================================
	string overseerHostname = null;
	string overseerUsername = null;
	string workerHostname = null;
	string workerUsername = null;
/+
`~`    --overseer-hostname=<host> The hostname or external IP address of the
`~`                               local machine that is requesting CPU time from
`~`                               the worker machine.  This must be the hostname/
`~`                               address as seen from the worker machine; so
`~`                               adjust this needed when the overseer is behind
`~`                               a firewall or subnet.
`~`                               By default, this will be set to the hostname
`~`                               returned by the system's gethostname() function.
`~`
`~`    --overseer-address=<addr>  Does the same thing as --overseer-hostname.
`~`
`~`    --overseer-username=<user> The username that the worker machine is to use
`~`                               when authenticating itself to the overseer
`~`                               machine.  By default, this is the current
`~`                               user name.
`~`
`~`    --worker-hostname=<host>   The hostname of IP address of the machine that
`~`                               is to perform the computation.
`~`                               This parameter is required.
`~`
`~`    --worker-address=<addr>    Does the same thing as --worker-hostname.
`~`
`~`    --worker-username=<user>   The username that is used when the overseer
`~`                               authenticates itself to the worker.
`~`                               By default, this is the guest account.
+/
	auto helpInformation = std.getopt.getopt(args,
		"overseer-hostname|overseer-address",
			"The hostname or external IP address of the local machine that "~
			"is requesting CPU time from the worker machine.  This must be "~
			"the hostname/address as seen from the worker machine; so adjust "~
			"this needed when the overseer is behind a firewall or subnet.  "~
			"By default, this will be set to the IP address configured on "~
			"the system's first active (up) non-loopback TCP/IP interface.",
				&overseerHostname,
		"overseer-username",
			"The username that the worker machine is to use when "~
			"authenticating itself to the overseer machine.  By default, "~
			"this is the current user name.",
				&overseerUsername,
		"worker-hostname|worker-address",
			"The hostname of IP address of the machine that is to perform the "~
			"computation.  This parameter is required.",
				&workerHostname,
		"worker-username",
			"The username that is used when the overseer authenticates itself "~
			"to the worker.  By default, this is the guest account.",
				&workerUsername);


	// =====================================================================
	//            ----- Compute parameters and configuration -----
	// =====================================================================
	ulong sessionId = std.random.uniform(0UL,ulong.max);
	string sessionIdStr = std.conv.toChars!16(sessionId).array;

	if ( workerHostname is null )
	{
		// TODO: We really need a better Getopt printer.
		defaultGetoptPrinter(usage, helpInformation.options);
		stderr.writeln("");
		stderr.writeln("Error: --worker-hostname is a required parameter.");
		return 1;
	}

	// Get the maximum possible buffer size needed for the getpwuid_r function.
	// (and allocate the buffer).
	auto bufSize = core.sys.posix.unistd.sysconf(_SC_GETPW_R_SIZE_MAX);
	if ( bufSize < 0 )
		throw PosixException.whenCalling("sysconf", errno);

	auto passwdBuffer = new char[bufSize];
	passwd overseerPasswdStruct;
	passwd* overseerPasswdStructReturned;

	// Get our UID and related information.
	// Note that this means "passwd" in the sense of the Linux/UNIX /etc/passwd
	// file; this specific snippet does not actually work with passwords.
	if ( overseerUsername is null )
	{
		uint overseerUserId = core.sys.posix.unistd.getuid();
		auto ret = core.sys.posix.pwd.getpwuid_r(
			overseerUserId,
			&overseerPasswdStruct,
			passwdBuffer.ptr,
			passwdBuffer.length,
			&overseerPasswdStructReturned);
		if ( ret != 0 )
			throw PosixException.whenCalling("getpwuid_r", errno);

		overseerUsername = overseerPasswdStruct.pw_name.fromStringz().assumeUnique();
	}

	// Get the our hostname/ip.
	if ( overseerHostname is null )
		overseerHostname = getDefaultIpAddr();

	/+
	bufSize = core.sys.posix.unistd.sysconf(_SC_HOST_NAME_MAX) + 1;
	if ( bufSize < 0 )
		throw PosixException.whenCalling("sysconf", errno);
	auto hostnameBuf = new char[bufSize];
	ret = core.sys.posix.unistd.gethostname(hostnameBuf.ptr, hostnameBuf.length);
	if ( ret != 0 )
		throw PosixException.whenCalling("gethostname", errno);

	auto overseerHostName = hostnameBuf.ptr.fromStringz().assumeUnique();
	+/

	if ( workerUsername is null )
		workerUsername = "guest";

	writefln("My username is %s and my session-id is %s", overseerUsername, sessionIdStr);
	writefln("My IP address or hostname is %s", getDefaultIpAddr());

	// TODO: BUG: Make environment.get accept a buffer (for secure memory) and
	//            get the patch accepted into phobos.
	// (For now we will just copy it into secure memory.  This still isn't very
	// secure, but it will allow other means of acquiring the password to be
	// secure.)
	SecureMem!(char[]) workerPassword = null;
	auto workerPasswordEnv = std.process.environment.get("REMOTELY_WORKER_PASSWORD");
	if ( workerPasswordEnv )
	{
		// Note: it is important that the resulting slice is null-terminated,
		//       because this will be passed into C functions later.
		//       The rest of the code will use .ptr when sending secured
		//       memory into C functions.  This avoids any risk that
		//       .toStringz() will copy confidential information into memory
		//       that doesn't get scrubbed later (or otherwise secured correctly).
		//char[] secureMem = cast(char[])security.secureMalloc(workerPasswordEnv.length+1);
		workerPassword = SecureMem!(char[])(security.secureMalloc(workerPasswordEnv.length+1));
		workerPassword[0..$-1] = workerPasswordEnv;
		workerPassword[$-1] = '\0';
		workerPassword = workerPassword[0..$-1];
	}

	// =====================================================================
	//                        ----- Do work! -----
	// =====================================================================
	auto sessionObj = cliStartSshSession(workerHostname, workerUsername, workerPassword);
	scope(exit)
		cliEndSshSession(sessionObj);

	auto channel = startNoninteractiveShell(sessionObj);
	scope(exit)
		endNoninteractiveShell(channel);


	//genKeyPair();

	// TODO: Try just using SSHFS instead?
	// Hmmm, maybe we can automatically establish private-public key encryption
	// for the worker machine so that it can log in as our user without any
	// need for a password.  (When logging into the worker initially, just use
	// a guest account.  Maybe have a --worker-username parameter to allow
	// the initial login to be changed.)

	// The mount.cifs documentation states that if the "password" option is not
	// given, then the PASSWD environment variable will be used.  We can exploit
	// this to provide the password to the mount command without needing to
	// pass it as an argument.  We don't want to pass it as an argument because
	// the arguments are visible from commands like "ps" and "top" that show
	// processes and their arguments (passing a password as an argument is
	// always a security vulnerability).
	//exec(`PASSWD='%s' mount.cifs -o username=%s`, TODO:overseerPassword, overseerUserName);
	return 0;
}

import c.openssl.bio;
import c.openssl.err;
import c.openssl.ec;
import c.openssl.pem;

enum ECCTYPE = "secp521r1";

void genKeyPair() {
	import core.stdc.stdio;

	BIO               *outbio = null;
	EC_KEY            *myecc  = null;
	EVP_PKEY          *pkey   = null;
	int               eccgrp;

	/* ---------------------------------------------------------- *
	* These function calls initialize openssl for correct work.  *
	* ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	/* ---------------------------------------------------------- *
	* Create the Input/Output BIO's.                             *
	* ---------------------------------------------------------- */
	//outbio = BIO_new(BIO_s_file());
	outbio = BIO_new_fp(core.stdc.stdio.stdout, BIO_NOCLOSE);

	/* ---------------------------------------------------------- *
	* Create a EC key sructure, setting the group type from NID  *
	* ---------------------------------------------------------- */
	eccgrp = OBJ_txt2nid("secp521r1");
	myecc = EC_KEY_new_by_curve_name(eccgrp);

	/* -------------------------------------------------------- *
	* For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag*
	* ---------------------------------------------------------*/
	EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

	/* -------------------------------------------------------- *
	* Create the public/private EC key pair here               *
	* ---------------------------------------------------------*/
	if (! (EC_KEY_generate_key(myecc)))
		BIO_printf(outbio, "Error generating the ECC key.");

	/* -------------------------------------------------------- *
	* Converting the EC key into a PKEY structure let us       *
	* handle the key just like any other key pair.             *
	* ---------------------------------------------------------*/
	pkey=EVP_PKEY_new();
	if (!EVP_PKEY_assign_EC_KEY(pkey,myecc))
		BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");

	/* -------------------------------------------------------- *
	* Now we show how to extract EC-specifics from the key     *
	* ---------------------------------------------------------*/
	myecc = EVP_PKEY_get1_EC_KEY(pkey);
	const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);

	/* ---------------------------------------------------------- *
	* Here we print the key length, and extract the curve type.  *
	* ---------------------------------------------------------- */
	BIO_printf(outbio, "ECC Key size: %d bit\n", EVP_PKEY_bits(pkey));
	BIO_printf(outbio, "ECC Key type: %s\n", OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));

	/* ---------------------------------------------------------- *
	* Here we print the private/public key data in PEM format.   *
	* ---------------------------------------------------------- */
	if(!PEM_write_bio_PrivateKey(outbio, pkey, null, null, 0, null, null))
		BIO_printf(outbio, "Error writing private key data in PEM format");

	if(!PEM_write_bio_PUBKEY(outbio, pkey))
		BIO_printf(outbio, "Error writing public key data in PEM format");

	/* ---------------------------------------------------------- *
	* Free up all structures                                     *
	* ---------------------------------------------------------- */
	EVP_PKEY_free(pkey);
	EC_KEY_free(myecc);
	BIO_free_all(outbio);
}
