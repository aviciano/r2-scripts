(function () {
	const plugin = "checksec";

	const ESC = "\033[";
	const ansiEscapeSeq = (code, content) => `${ESC}${code}m${content}${ESC}m`;
	const orange = (content) => ansiEscapeSeq(33, content);
	const green = (content) => ansiEscapeSeq(32, content);
	const red = (content) => ansiEscapeSeq(31, content);

	const checkRELRO = (info) => {
		const relro = info.bin.relro;

		if (relro === "no")
			return red("No RELRO");
		if (relro === "partial")
			return orange("Partial RELRO");
		if (relro === "full")
			return green("Full RELRO");

		return `TODO unknown ${relro}`;
	};

	const checkStackCanary = (info) => {
		return info.bin.canary
			? green("Canary found")
			: red("No canary found");
	};

	const checkNX = (info) => {
		return info.bin.nx
			? green("NX enabled")
			: red("NX disabled");
	};

	const checkPIE = (info) => {
		return info.bin.pic
			? green("PIE enabled")
			: red("No PIE");
	};

	const checkRPath = (info) => {
		const rpath = info.bin.rpath;
		return (rpath === "NONE")
			? green("No RPATH")
			: red(`RPATH = "${rpath}"`);
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

