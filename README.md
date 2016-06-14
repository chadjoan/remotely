remotely
===

```
This project is a work in progress.  It doesn't actually connect yet ;)

Usage: remotely --worker-hostname=<host> [<options>] -- <command> [<args> ...]

The remotely program allows the given <command> to be executed using the CPU
resources of another machine, while still behaving as if it were being
executed locally.

This is similar to process migration: a local program using local data is
executed as a process on another machine.  However, this program differs from
other process migration methodologies in several ways:
 - It has very few dependencies.  Both machines involved must have SSH available
     and be running SSH daemons.
 - It requires no setup in advance.  Existing systems can use this tool to start
     processes on other existing systems.  It does not require kernel modules,
     special filesystems, or any such mechanisms be installed before work can
     proceed.
 - It cannot migrate existing processes.  The user must know which machine
     they want to run their process on when they start executing it.
 - It is binary in nature, and cannot be used to extract CPU resources from
     multiple machines.  Of course, if the worker machine is a virtualized system,
     then this tool makes it possible for a non-virtualized system to take
     advantage of any number of physical machines that might pool resources for
     the virtualized system.
 - Security-wise, the overseer machine must trust the worker machine.

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

Options:
    --overseer-hostname=<host> The hostname or external IP address of the
                               local machine that is requesting CPU time from
                               the worker machine.  This must be the hostname/
                               address as seen from the worker machine; so
                               adjust this needed when the overseer is behind
                               a firewall or subnet.
                               By default, this will be set to the hostname
                               returned by the system's gethostname() function.

    --overseer-address=<addr>  Does the same thing as --overseer-hostname.

    --overseer-username=<user> The username that the worker machine is to use
                               when authenticating itself to the overseer
                               machine.  By default, this is the current
                               user name.

    --worker-hostname=<host>   The hostname of IP address of the machine that
                               is to perform the computation.
                               This parameter is required.

    --worker-address=<addr>    Does the same thing as --worker-hostname.

    --worker-username=<user>   The username that is used when the overseer
                               authenticates itself to the worker.
                               By default, this is the guest account.
```
