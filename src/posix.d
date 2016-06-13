module posix;

class PosixException : Exception
{
	private int _errno;
	protected @property int errno(int errno) { return _errno = errno; }
	public @property int errno() const { return _errno; }

	public static PosixException whenCalling(string posixFunctionCalled, int errno,
		string file = __FILE__, size_t line = __LINE__)
	{
		string msg =
			"Call to "~posixFunctionCalled~" failed. Error is as follows: \n";

		return new PosixException(msg, errno, file, line);
	}

	this(string msg, int errno, string file = __FILE__, size_t line = __LINE__)
	{
		super(msg ~ getPosixError(errno), file, line);
	}

	private string getPosixError(int errno)
	{
		import core.stdc.string;
		import std.string : fromStringz;
		import std.exception : assumeUnique;

		version (CRuntime_Glibc)
		{
			char[1024] buf = void;
			auto s = core.stdc.string.strerror_r(errno, buf.ptr, buf.length);
		}
		else
		{
			auto s = core.stdc.string.strerror(errno);
		}
		return s.fromStringz().assumeUnique();
	}
}