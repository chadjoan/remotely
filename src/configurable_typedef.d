module configurable_typedef;

struct TypedefConfig
{
	bool strictAssignment = true; /// Reject operations where the typedef'd type is being assigned a value from the original type?
	bool strictBinary = true;     /// Reject binary operations with the original type?
	bool strictMutation = true;   /// Reject mutation (ex: opAssign) that introduces values from the original type?
	bool strictCompare = true;    /// Reject comparison against the original type?
	bool strictElements = true;   /// Reject element-wise copy/modify operations with the original type?
}

mixin template ConfigurableTypedef(T, TypedefConfig config, T init = T.init, string cookie=null)
{
	//import std.array;
	//import std.conv;
	import std.traits;
	//import std.typecons;
/+
	private alias Typedef!(T, T.init, "SecureMem") SecureMemGuts;
	private SecureMemGuts payload;
	alias payload this;

	this(typeof(null) n) { payload = n; }
	this(T t) { payload = t; }
	static if ( isArray!T )
		this(void[] t) { payload = SecureMemGuts(cast(T)t); }

	//void opAssign(typeof(null) n) { payload = n; }
	static if ( isArray!T )
		void opAssign(void[] t) { payload = SecureMemGuts(cast(T)t); }

	static if ( isArray!T ) {
		@property bool empty() const {
			return (cast(T)payload).empty();
		}
	}
+/

	private T payload = init;

	private static bool isNullable(Q)() {
		static if (__traits(compiles, { Q q = null; }))
			return true;
		else
			return false;
	}

	this(X)(X x) { payload = x; }

	auto opUnary(string op)() { mixin("return typeof(this)("~op~"payload);"); }
	ref T opCast(X : T)() { return payload; }
	auto ref opCast(X)() { return cast(X)payload; }

	auto opBinary(string op, R)(R rhs) if(!config.strictBinary || !is(R==T)) {
		mixin("return typeof(this)(payload "~op~" rhs.payload);");
	}

	bool opEquals(R)(auto ref const R rhs) const
		if(!config.strictCompare || !is(R==T))
	{
		return payload == rhs.payload;
	}

	static if ( isNullable!T )
		bool opEquals(typeof(null) rhs) const { return payload == rhs; }

	int opCmp(R)(auto ref const R rhs) const
		if(!config.strictCompare || !is(R==T))
	{
		static if (__traits(compiles, payload.opCmp(rhs.payload) ))
			return payload.opCmp(rhs.payload);
		else
		{
			// TODO: This could probably be better.
			// (Maybe at least special-case a faster version for numeric types?)
			if ( this.opEquals(rhs) )
				return 0;
			else if ( this.payload < rhs.payload )
				return -1;
			else
				return 1;
		}
	}

	auto opOpAssign(string op, R)(auto ref const R rhs)
		if(!config.strictMutation || !is(R==T))
	{
		mixin("return typeof(this)(this.payload "~op~" rhs.payload);");
	}

	static if ( isArray!T )
	{
		// Hmmm... multidimensional arrays?
		private alias E = typeof({ T x; return x[0]; }());

		private struct ConfigurableTypedefSlice
		{
			size_t lo;
			size_t hi;

			this( size_t lo, size_t hi ) {
				this.lo = lo;
				this.hi = hi;
			}
		}

		private template buildIndexList(int at, IndexTypes...)
		{
			import std.conv;
			static if ( IndexTypes.length == 1 )
				private const string comma = "";
			else
				private const string comma = ", ";

			static if ( IndexTypes.length == 0 )
				const string buildIndexList = "";
			else static if ( is(ConfigurableTypedefSlice == IndexTypes[0]) )
				const string buildIndexList =
					"indices["~ to!string(at) ~"].lo .. indices["~ to!string(at) ~"].hi"~
					comma ~ buildIndexList!(at, IndexTypes[1..$]);
			else
				const string buildIndexList =
					"indices["~ to!string(at) ~"]"~
					comma ~ buildIndexList!(at, IndexTypes[1..$]);
		}

		private template buildIndexList(IndexTypes...)
		{
			alias buildIndexList = buildIndexList!(0,IndexTypes);
		}

		auto opIndexUnary(string op, A...)(A indices) { mixin("return typeof(this)("~op~"payload[indices]);"); }

		// ----- opIndexAssign ------

		auto opIndexAssign(R,A...)(R rhs, A indices)
			if(!config.strictElements || !is(R==T))
		{
			//import std.conv;
			static if (__traits(compiles, payload.opIndexAssign(rhs,indices) ))
			{
				//pragma(msg, std.conv.to!string(__LINE__));
				return payload.opIndexAssign(expr,indices);
			}
			else
			{
				const string expr = "payload["~ buildIndexList!A ~"] = rhs";
				alias Q = typeof(mixin(expr));

				//pragma(msg, std.conv.to!string(__LINE__)~": "~ Q.stringof ~" "~expr~" ("~R.stringof~")");
				static if ( is(Q==T) || is(Q==typeof(this)) ) {
					mixin("return typeof(this)("~ expr ~");");
				}
				else static if ( is(E==Q) ) {
					mixin("return "~expr~";");
				}
				else {
					static assert(0);
				}
			}
		}

		/+
		auto opIndexAssign(Q, X:typeof(this))(Q expr, X slice)
			if(!config.strictElements || !is(Q==T))
		{
			import std.conv;
			pragma(msg, std.conv.to!string(__LINE__)~": "~ Q.stringof);
			return typeof(this)(slice.payload = expr);
		}

		auto opIndexAssign(Q, X)(Q expr, X slice)
			if(!config.strictElements || !is(Q==T))
		{
			import std.conv;
			pragma(msg, std.conv.to!string(__LINE__));
			return typeof(this)(this.payload.opIndexAssign(expr,slice));
		}+/

		auto opIndexAssign(R)(R rhs)
			if(!config.strictElements || !is(R==T))
		{
			//import std.conv;
			//pragma(msg, std.conv.to!string(__LINE__));
			return typeof(this)(this.payload[] = rhs);
		}

		// ----- opIndexOpAssign ------

		auto opIndexOpAssign(string op, R, A...)(R rhs, A indices)
			if(!config.strictElements || !is(Q==T))
		{
			//import std.conv;
			static if (__traits(compiles, payload.opIndexOpAssign!op(rhs,indices) ))
			{
				//pragma(msg, std.conv.to!string(__LINE__));
				return payload.opIndex(indices); // Forward T-defined slices.
			}
			else
			{
				const string expr = "payload["~ buildIndexList!A ~"] "~op~" rhs";
				alias Q = typeof(mixin(expr));

				//pragma(msg, std.conv.to!string(__LINE__)~": T is "~ T.stringof);
				//pragma(msg, std.conv.to!string(__LINE__)~": "~ Q.stringof ~" "~expr);
				static if ( is(T:Q) || is(Q==typeof(this)) ) {
					mixin("return typeof(this)("~ expr ~");");
				}
				else static if ( is(E:Q) ) {
					mixin("return "~expr~";");
				}
				else {
					static assert(0);
				}
			}
		}

		/+
		auto opIndexOpAssign(string op, Q, X:typeof(this))(Q expr, X slice)
			if(!config.strictElements || !is(Q==T))
		{
			mixin("return typeof(this)(slice.payload "~op~" expr);");
		}

		auto opIndexOpAssign(string op, Q, X)(Q expr, X slice)
			if(!config.strictElements || !is(Q==T))
		{
			return typeof(this)(this.payload.opIndexOpAssign!op(expr,slice));
		}
		+/

		auto opIndexOpAssign(string op, R)(R rhs)
			if(!config.strictElements || !is(R==T))
		{
			mixin("return typeof(this)(this.payload[] "~op~" rhs);");
		}

		// ----- opIndex ------
		auto opIndex(A...)(A indices) {
			//import std.conv;
			static if (__traits(compiles, payload.opIndex(indices) ))
			{
				//pragma(msg, std.conv.to!string(__LINE__));
				return payload.opIndex(indices); // Forward T-defined slices.
			}
			else
			{
				const string expr = "payload["~ buildIndexList!A ~"]";
				alias Q = typeof(mixin(expr));

				//pragma(msg, std.conv.to!string(__LINE__)~": T is "~ T.stringof);
				//pragma(msg, std.conv.to!string(__LINE__)~": "~ Q.stringof ~" "~expr);
				static if ( is(T:Q) || is(Q==typeof(this)) ) {
					mixin("return typeof(this)("~ expr ~");");
				}
				else static if ( is(E:Q) ) {
					mixin("return "~expr~";");
				}
				else {
					static assert(0);
				}
			}
		}

		auto opIndex() { return typeof(this)(this.payload[]); }

		// ----- opSlice and opDollar ------
		auto opSlice(size_t dim,N1,N2)(N1 lo, N2 hi) const
			if ( isIntegral!N1 && isIntegral!N2 )
		{
			static if (__traits(compiles, payload.opSlice!dim(lo,hi) ))
				return payload.opSlice!dim(lo,hi); // Forward T-defined slices.
			else
				return ConfigurableTypedefSlice(lo,hi); // For built-in types.
		}

		auto opDollar(size_t dim)() const
		{
			//import std.conv;
			//pragma(msg, std.conv.to!string(__LINE__));
			static if (__traits(compiles, payload.opDollar!dim() ))
				return payload.opDollar!dim();
			else
				return payload.length;
		}

		static if ( !config.strictElements && __traits(compiles, payload.ptr) )
			@property auto ptr() { return payload.ptr; }

		static if (__traits(compiles, payload.length ))
		{
			@property auto length() const { return payload.length; }

			static if ( !__traits(compiles, payload.empty) )
				@property bool empty() const { return payload.length == 0; }
		}
	}

	/+static typeof(this) opAssign(T t) {
		typeof(this) ret;
		ret.payload = t;
		return ret;
	}+/
	//static void opAssign(T t) { return typeof(this)(t); }
	//static void opAssign(typeof(null) n) { return typeof(this)(n); }
	/+void opAssign(T t) { payload = t; }
	void opAssign(typeof(null) n) { payload = n; }
	static if ( isArray!T )
		void opAssign(void[] t) { payload = cast(T)t; }
	+/
	//@property auto ref T data() const { return (cast(T)payload); }

	auto toString() const {
		import std.conv;
		return payload.to!string();
	}

	@property auto ref data() { return payload; }

}

// TODO: This needs A LOT more static asserts, and probably some unittests.



struct StrongTypedef(T, T init = T.init, string cookie=null)
{
	mixin ConfigurableTypedef!(T, TypedefConfig(), init, cookie);
}


static assert( is( StrongTypedef!int == typeof({
	StrongTypedef!int x;
	StrongTypedef!int y;
	return x + y; }()))
);

static assert( is( StrongTypedef!(char[]) == typeof({
	StrongTypedef!(char[]) x;
	StrongTypedef!(char[]) y;
	return x ~ y; }()))
);


static assert( is( StrongTypedef!(char[]) == typeof({
	StrongTypedef!(char[]) x;
	return x[0..$]; }()))
);
