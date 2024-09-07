(function () {
	const plugin = "checksec";

	const checkRELRO = (info) => {
		const relro = info.bin.relro;

		if (relro === "no")
			return "\033[31mNo RELRO\033[m";
		if (relro === "partial")
			return "\033[33mPartial RELRO\033[m";
		if (relro === "full")
			return "\033[32mFull RELRO\033[m";

		return `TODO unknown ${relro}`;
	};

	const checkStackCanary = (info) => {
		return info.bin.canary
			? "\033[32mCanary found\033[m"
			: "\033[31mNo canary found\033[m";
	};

	const checkNX = (info) => {
		return info.bin.nx
			? "\033[32mNX enabled\033[m"
			: "\033[31mNX disabled\033[m";
	};

	const checkPIE = (info) => {
		return info.bin.pic
			? "\033[32mPIE enabled\033[m"
			: "\033[31mNo PIE\033[m";
	};

	const checkRPath = (info) => {
		const rpath = info.bin.rpath;
		return (rpath === "NONE")
			? "\033[32mNo RPATH\033[m"
			: "\033[31m" + `RPATH = "${rpath}"` + "\033[m";
	};

	const checkInsecureFunc = (symbols) => {
		const functions = symbols.filter(s => s.type === "FUNC").sort(s => s.name);
		const unsafe = functions.filter(s => "unsafe" in s);
		console.log(`Found #${unsafe.length} potentially insecure function(s).`);

		const padLength = unsafe
			.map(f => f.name.length)
			.reduce((prev, len) => Math.max(prev, len)) + 1;

		for (const func of unsafe) {
			console.log(`  ${func.name.padEnd(padLength)} : ${func.unsafe}`);
		}
	};

	/*
	const checkInsecureFunc = (symbols) => {
		const functions = symbols.filter(s => s.type === "FUNC").sort(s => s.name);
		console.log(`Analyzing #${functions.length} imported functions ...`);

		// https://github.com/0xdea/semgrep-rules/blob/main/c/insecure-api-*.yaml
		// https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java
		// https://github.com/git/git/blob/master/banned.h
		const tiers = [
			{
				"desc": "these functions are generally considered insecure",
				"names": [
					// strcpy family
					"strcpy", "_strcpy", "strcpyA", "strcpyW", "wcscpy", "_wcscpy", "_tcscpy", "mbscpy", "_mbscpy", 
					"StrCpy", "StrCpyA", "StrCpyW", 
					"lstrcpy", "lstrcpyA", "lstrcpyW", "_tccpy", "_mbccpy", "_ftcscpy",
					"stpcpy", "wcpcpy",
					// strcat family
					"strcat", "_strcat", "strcatA", "strcatW", "wcscat", "_wcscat", "_tcscat", "mbscat", "_mbscat", 
					"StrCat", "StrCatA", "StrCatW", 
					"lstrcat", "_lstrcat", "lstrcatA", "_lstrcatA", "lstrcatW", "_lstrcatW", 
					"StrCatBuff", "StrCatBuffA", "StrCatBuffW", "StrCatChainW", 
					"_tccat", "_mbccat", "_ftcscat",
					// sprintf family
					"sprintf", "_sprintf", "_sprintf_c89", 
					"vsprintf", "_vsprintf", "_vsprintf_c89", 
					"_wsprintfA", "_wsprintfW", "sprintfW", "sprintfA", 
					"wsprintf", "_wsprintf", "wsprintfW", "_wsprintfW", "wsprintfA", "_wsprintfA",
					"_stprintf", "wvsprintf", "wvsprintfA", "wvsprintfW", "_vstprintf",
					// scanf family
					"scanf", "_scanf", "__isoc99_sscanf", "wscanf", "_tscanf", "sscanf", "_sscanf", "_sscanf_c89", 
					"fscanf", "_fscanf", "__isoc99_fscanf", "vfscanf", "_vfscanf", "fwscanf", "swscanf", "_stscanf",
					"snscanf", "_snscanf", "snwscanf", "_snwscanf", "_sntscanf", "vsscanf", "_vsscanf",
					"vscanf", "_vscanf", "vfwscanf", "_vfwscanf", "vswscanf", "_vswscanf", "vwscanf", "_vwscanf",
					// gets family
					"gets", "_gets", "_getts", "_getws", "_gettws", "getpw", "getpass", "getc", "getchar",
					// insecure memory allocation on the stack, can also cause stack clash
					"alloca", "_alloca",
					// command execution via shell
					"system", "_system", "popen", "_popen", "wpopen", "_wpopen",
					// insecure temporary file creation
					"mktemp", "tmpnam", "tempnam",
					// insecure pseudo-random number generator
					"rand", "rand_r", "srand"
				],
			},
			{
				"desc": "these functions are interesting and should be checked for insecure use cases",
				"names": [
					// strncpy needs explicit null-termination: buf[sizeof(buf) – 1] = '\0'
					"strncpy", "_strncpy", "wcsncpy", "_tcsncpy", "_mbsncpy", "_mbsnbcpy",
					"StrCpyN", "StrCpyNA", "StrCpyNW", "StrNCpy", "strcpynA", "StrNCpyA", "StrNCpyW", 
					"lstrcpyn", "lstrcpynA", "lstrcpynW", "_csncpy", "wcscpyn",
					"stpncpy", "wcpncpy",
					// strncat must be called with: sizeof(buf) - strlen(buf) - 1 to prevent off-by-one bugs (beware of underflow)
					"strncat", "_strncat", "wcsncat", "_tcsncat", "_mbsncat", "_mbsnbcat", 
					"StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA", "StrNCatW", 
					"lstrncat", "lstrcatnA", "lstrcatnW", "lstrcatn",
					// strlcpy returns strlen(src), which can be larger than the dst buffer
					"strlcpy", "wcslcpy",
					// strlcat returns strlen(src) + strlen(dst), which can be larger than the dst buffer
					"strlcat", "wcslcat",
					// strlen can be dangerous with short integers (and potentially also with signed int)
					"strlen", "lstrlen", "strnlen", "wcslen", "wcsnlen",
					// string token functions can be dangerous as well
					"strtok", "_tcstok", "wcstok", "_mbstok",
					// snprintf returns strlen(src), which can be larger than the dst buffer
					"snprintf", "_sntprintf", "_snprintf", "_snprintf_c89", "_snwprintf", 
					"vsnprintf", "_vsnprintf", "_vsnprintf_c89",
					"vsnwprintf", "_vsnwprintf", "wnsprintf", "wnsprintfA", "wnsprintfW", "_vsntprintf", 
					"wvnsprintf", "wvnsprintfA", "wvnsprintfW",
					"swprintf", "_swprintf", "vswprintf", "_vswprintf",
					// memory copying functions can be used insecurely, check if size arg can contain negative numbers
					"memcpy", "_memcpy", "memccpy", "memmove", "_memmove", "bcopy", "memset",
					"wmemcpy", "_wmemcpy", "wmemmove", "_wmemmove", "RtlCopyMemory", "CopyMemory",
					"memcpy_s", "wmemcpy_s", "memmove_s", "wmemmove_s", "memset_s", "memset_explicit",
					// user id and group id functions can be used insecurely, return value must be checked
					"setuid", "seteuid", "setreuid", "setresuid",
					"setgid", "setegid", "setregid", "setresgid", "setgroups", "initgroups",
					// exec* and related functions can be used insecurely
					// functions without "-e" suffix take the environment from the extern variable environ of calling process
					"execl", "execlp", "execle", "execv", "execve", "execvp", "execvpe",
					"_execl", "_execlp", "_execle", "_execv", "_execve", "_execvp", "_execvpe",
					"fork", "vfork", "clone", "pipe",
					// i/o functions can be used insecurely
					"open", "open64", "openat", "openat64", "fopen", "fopen64", "freopen", "freopen64", "dlopen", "connect",
					"read", "fread", // check read from unreadable paths/files and from writable paths/files
					"write", "fwrite", // check write to unwritable paths/files
					"recv", "recvfrom", // check for null-termination
					"fgets",
					// kernel copy functions can be used insecurely and cause infoleaks or buffer overflows
					"copy_from_user", "copy_to_user", "get_user", "put_user", "copyin", "copyout"
				],
			},
			{
				"desc": "code paths involving these functions should be carefully checked",
				"names": [
					// check for insecure use of environment vars
					"getenv", "setenv", "putenv", "unsetenv",
					// check for insecure use of arguments
					"getopt", "getopt_long",
					// check for insecure use of memory allocation functions
					// check if size arg can contain negative numbers or zero, return value must be checked
					"malloc", "xmalloc",
					"calloc", // potential implicit overflow due to integer wrapping
					"realloc", "xrealloc", "reallocf", // doesn't initialize memory to zero; realloc(0) is equivalent to free
					"valloc", "pvalloc", "memalign", "aligned_alloc", "vzalloc",
					"kmalloc", "kmalloc_array", "kcalloc", "kzalloc", "mallocarray",
					"free", "_free", "kfree", // check for incorrect use, double free, use after free
					// check for file access bugs
					"mkdir", "creat",
					"link", "linkat", "symlink", "symlinkat", "readlink", "readlinkat", "unlink", "unlinkat", "realpath", "PathAppend",
					"rename", "renameat",
					"stat", "lstat", "fstat", "fstatat",
					"chown", "lchown", "fchown", "fchownat",
					"chmod", "fchmod", "fchmodat",
					"access", "faccessat", "access_ok",
					"getwd", "getcwd",
					// check for temporary file bugs
					"mkstemp", "mkstemp64", "tmpfile", "mkdtemp",
					// check for makepath and splitpath bugs
					"makepath", "_tmakepath", "_makepath", "_wmakepath", 
					"_splitpath", "_tsplitpath", "_wsplitpath",
					// check for format string bugs
					"syslog", "NSLog",
					"printf", "fprintf", "wprintf", "fwprintf", "asprintf", "dprintf", "printk",
					"vprintf", "vfprintf", "vasprintf", "vdprintf", "vfwprintf", 
					"vcprintf", "vcwprintf", "vscprintf", "vscwprintf", "vwprintf",
					"_printf", "_fprintf", "_wprintf", "_fwprintf", "_asprintf", "_dprintf", "_printk",
					"_vprintf", "_vfprintf", "_vasprintf", "_vdprintf", "_vfwprintf", 
					"_vcprintf", "_vcwprintf", "_vscprintf", "_vscwprintf", "_vwprintf",
					"_printf_c89", "_fprintf_c89",
					"err", "errx", "warn", "warnx", "verr", "verrx", "vwarn", "vwarnx",
					// check for locale bugs
					"setlocale", "catopen"
					// kill, signal/sigaction, *setjmp/*longjmp functions should be checked for signal-handling vulnerabilities
					// *sem*, *mutex* functions should be checked for other concurrency-related vulnerabilities
					// new, new []: potential implicit overflow with scalar constructor
					// delete, delete []: check for misalignment with constructor 
					// integer bugs should be also taken into account as they are more subtle and widespread
				],
			},
		];

		for (const tier of tiers) {
			const found = functions
				.filter(func => tier.names.find (name => func.name.endsWith(name)));

			if (found.length > 0)
				console.log(`${tier.desc} => ${JSON.stringify(found)}`);
		}
	};
	*/

	const coreCall = (cmd) => {
		if (!cmd.startsWith(plugin)) {
			return false;
		}

		const args = cmd.substr(plugin.length).trim();

		if (args.startsWith("-h") || args.startsWith("?")) {
			console.log(`Usage: ${plugin} [args]`);
			console.log(`  ${plugin} -h           - show this help`);
			console.log(`  ${plugin}              - list security properties of the current binary`);
		} else if (args === "") {
			const info = r2.cmdj("ij");
			console.log(`RELRO         : ${checkRELRO(info)}`);
			console.log(`STACK CANARY  : ${checkStackCanary(info)}`);
			console.log(`NX            : ${checkNX(info)}`);
			console.log(`PIE           : ${checkPIE(info)}`);
			console.log(`RPATH         : ${checkRPath(info)}`);

			const symbols = r2.cmdj("isj");
			checkInsecureFunc(symbols);
		}
		return true;
	};

	r2.unload("core", plugin);
	r2.plugin("core", () => {
		console.log(`==> The '${plugin}' plugin has been instantiated. Type '${plugin}' to test it`);
		return {
			"name": plugin,
			"license": "GPL3",
			"desc": "core plugin to check the security properties of executables",
			"author": "aviciano",
			"call": coreCall,
		};
	});
})();

