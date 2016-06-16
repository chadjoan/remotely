module security;

import c.openssl.crypto;

import std.string : toStringz, fromStringz;

import configurable_typedef;

/// A wrapper struct used to indicate that the given T is allocated in secure
/// memory.
struct SecureMem(T)
{
	import std.traits;

	static immutable TypedefConfig secureMemConfig = {
		TypedefConfig config;
		config.strictCompare = false;
		config.strictElements = false;
		return config;
	}();

	mixin ConfigurableTypedef!(T, secureMemConfig);
	//alias payload this;

	private static bool isNullable(Q)() {
		static if (is(typeof({ Q q = null; })))
			return true;
		else
			return false;
	}

	this(X)(X x) { payload = x; }
	//static if ( isNullable!T )
	//	this(typeof(null) n) { payload = n; }
	static if ( isArray!T )
		this(void[] t) { payload = cast(T)t; }


}

///
class OutOfSecureMemoryException : Exception {
	this(string msg, string file = __FILE__, int line = __LINE__) {
		super(msg, file, line);
	}
}

void[] secureMalloc(size_t size, string file = __FILE__, int line = __LINE__)
{
	import std.string : format;
	void *mem = CRYPTO_malloc(cast(int)size, file.toStringz(), line);
	if ( mem == null )
		throw new OutOfSecureMemoryException(
			format("%s, %s: secureMalloc(%s) failed: Ran out of secure memory.",
			file, line, size), file, line);
	return mem[0..size];
}

/+
// After examining LibreSSL's source, I find that CRYPTO_free doesn't zero
// out the memory it releases, and there is no CRYPTO_free_clean function
// or equivalent.
// It does use explicit_bzero in CRYPTO_realloc_clean, so we will just borrow
// that C function and use it to ensure our memory gets zero'd when free'd.
//
// This is potentially fragile because LibreSSL could change their zeroing
// function at some time in the future and cause this code to break at link
// time.  Not sure how to hedge against that though.
//
private extern(C) @nogc void explicit_bzero(void* ptr, size_t len);

// ... nevermind, we can't even link with it to begin with.
+/

void secureFree(void[] mem, string file = __FILE__, int line = __LINE__)
{
	//explicit_bzero(mem.ptr, mem.length);
	(cast(ubyte[])mem)[] = 0;
	// But this could get optimized away by the compiler or linker.

	CRYPTO_free(mem.ptr);
}

void[] secureRealloc(void[] mem, size_t newSize, string file = __FILE__, int line = __LINE__)
{
	import std.string : format;
	void *newMem = CRYPTO_realloc_clean(mem.ptr, cast(int)mem.length, cast(int)newSize, file.toStringz(), line);
	if ( newMem == null )
		throw new OutOfSecureMemoryException(
			format("%s, %s: secureRealloc(%X,%s) failed: Ran out of secure memory.",
			file, line, mem.ptr, newSize), file, line);;

	return newMem[0 .. newSize];
}

/+
// NOTE: Below is untested code from when I was still trying to use the
//       OPENSSL_secure_* memory functions.
//       The "secure" allocator had a fixed-sized (tunable) heap, lacked a
//       realloc function, and had a function for displaying the amount of
//       memory used.
//       LibreSSL seems to have removed these "secure" memory handling functions
//       and just uses memory from the OS with zeroing on free.


// Allocate about a megabyte of secure heap.
// This program won't need that much for its own operations: it might
// store a key pair, maybe a password, a copy or two of those things,
// and maybe the shell script that will be sent to the other machine.
// We need to make this bigger nonetheless: it will be used by the
// LibreSSL library to store BIGNUMs and whatnot.  I have no idea how
// much memory that will eat, but I'd like to be safe (while at the
// same time respecting the local system's resources).
// TODO: It'd be nice if we could figure out a way to reallocate this
//   dynamically and expand-as-needed.
enum SECURE_HEAP_SIZE = (2<<20);

void initSecureHeap()
{
	if ( !CRYPTO_secure_malloc_initialized() )
	{
		if ( !CRYPTO_secure_malloc_init(SECURE_HEAP_SIZE, 64) )
			throw new Exception("Could not allocate secure heap.");
	}
}

void finalizeSecureHeap()
{
	CRYPTO_secure_malloc_done();
}

///
class OutOfSecureMemoryException : Exception {
	this(string msg, string file = __FILE__, size_t line = __LINE__) {
		super(msg, file, line);
	}
}

void[] secureMalloc(size_t sz, string file = __FILE__, long line = __LINE__)
{
	import core.exception;
	void *mem = CRYPTO_secure_malloc(sz, file.toStringz(), line);
	if ( mem == null )
		throw new OutOfSecureMemoryException(
			"%s, %s: secureMalloc(%s) failed: Ran out of secure memory."~
			"%s / %s bytes used on the secure heap before this allocation.",
			file, line, newSize, CYRPTO_secure_used(), SECURE_HEAP_SIZE);
	return mem[0..sz];
}

void secureFree(void[] mem, string file = __FILE__, long line = __LINE__)
{
	CRYPTO_secure_free(mem.ptr, file.toStringz(), line);
}

void[] secureRealloc(void[] mem, size_t newSize, string file = __FILE__, long line = __LINE__)
{
	size_t oldSize = OPENSSL_secure_actual_size(mem.ptr);
	if ( newSize == 0 )
	{
		secureFree(mem, file, line);
		return null;
	}
	if ( newSize == oldSize )
		return mem;
	else
	if ( newSize < oldSize )
	{
		// Shrinking.

		if ( oldSize > 4 && !(newSize < (oldSize * 3 / 4)) )
		{
			// The shrinking doesn't change much.
			// Heck, the caller might have passed the same size parameter that
			// they gave to secureMalloc or a previous call to secureRealloc
			// (and LibreSSL overallocated a little).
			// We don't stand a lot to gain here.
			// Don't waste time on library calls until we can free enough to
			// make it worthwhile.
			return mem;
		}

		try
			void[] newMem = secureMalloc(newSize, file, line);
		catch ( OutOfSecureMemoryException e )
		{
			// Whoops, don't do that.
			// We'll have to live with our over-allocated memory, because we
			// don't have enough room to allocate a smaller chunk to move to.
			return mem;
		}

		size_t actualSize = OPENSSL_secure_actual_size(mem.ptr);
		if ( actualSize == oldSize )
		{
			// If it doesn't allocate a smaller chunk, then we won't be able
			// to save any memory by copying.  We may as well just shrink our
			// "slice" (eg: do nothing).  In this case, we will give our test
			// allocation back to the heap.
			secureFree(newMem, file, line);
			return mem;
		}
		else
		{
			// The new allocation was productive and saved memory.
			// Copy contents into it and free the old block.
			newMem[0..oldSize] = mem[0..oldSize];
			secureFree(mem, file, line);
			return newMem;
		}
	}
	else // newSize > oldSize
	{
		// Expansion.
		// Note that in the typical mallocator, realloc is not required to
		// make any guarantees about the contents of the new memory
		// /when expanding/.  We will follow that model here.
		// (source: http://pubs.opengroup.org/onlinepubs/009695399/functions/realloc.html)

		// Despite the spec's relaxing of copy requirements, we still can't
		// free-then-allocate (which has a slightly higher chance of success)
		// because we are required to maintain the contents of the current
		// chunk of memory if the allocation fails.
		void* newMem = CRYPTO_secure_malloc(newSize, file.toStringz(), line);
		if ( newMem == null )
			throw new OutOfSecureMemoryException(
				"%s, %s: secureRealloc(%X,%s) failed: Ran out of secure memory."~
				"%s / %s bytes used on the secure heap before this allocation.",
				file, line, mem.ptr, newSize, CYRPTO_secure_used(), SECURE_HEAP_SIZE);

		secureFree(mem, file, line);

		return newMem[0..newSize];
	}
	assert(0);
}
+/