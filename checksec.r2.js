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

