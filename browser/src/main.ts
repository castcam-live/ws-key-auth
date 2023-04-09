import { connect, encodeBase64 } from "./lib";

const app = document.getElementById("app");
if (!app) throw new Error("DOM error");

const a = app;

async function websocketAddress(): Promise<string> {
	a.innerHTML = "Web Socket address: <input id='address-input' type='text'>";

	const promise = new Promise<string>((resolve) => {
		document
			.getElementById("address-input")
			?.addEventListener("keydown", (e) => {
				if (e.key === "Enter") {
					const address = (
						document.getElementById("address-input") as HTMLInputElement
					).value;
					resolve(address);
				}
			});
	});

	return await promise;
}

async function generateKeys() {
	return await crypto.subtle.generateKey(
		{ name: "ECDSA", namedCurve: "P-256" },
		false,
		["sign", "verify"]
	);
}

async function getClientId(keyPair: CryptoKeyPair) {
	const algo = keyPair.publicKey.algorithm;
	if (algo.name !== "ECDSA" && algo.name !== "ECDH") {
		throw new Error(
			`Unexpected key algorithm "${keyPair.publicKey.algorithm.name}"`
		);
	}
	const encodedRaw = encodeBase64(
		await crypto.subtle.exportKey("raw", keyPair.publicKey)
	);
	return `WebCrypto-raw.EC.${(algo as any).namedCurve}$${encodedRaw}`;
}

function sign(data: ArrayBuffer, keyPair: CryptoKeyPair): Promise<ArrayBuffer> {
	return crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		keyPair.privateKey,
		data
	);
}

async function connecting(address: string) {
	a.innerHTML = "Connecting...";

	// Generate a random P-256 key pair
	const keyPair = await generateKeys();

	const clientId = await getClientId(keyPair);

	const ws = new WebSocket(address);

	await connect(ws, clientId, (data) => {
		return sign(data, keyPair);
	});

	return ws;
}

async function done(ws: WebSocket) {
	a.innerHTML = `
		<p>Connected</p>
		<div><textarea id='input'></textarea></div>

		<div id="output">

		</div>
	`;

	const input = document.getElementById("input");
	if (!input) throw new Error("DOM error");

	input.addEventListener("keydown", (e) => {
		if (e.key === "Enter") {
			const data = (input as HTMLTextAreaElement).value;
			ws.send(data);
		}
	});

	ws.addEventListener("message", (e) => {
		const output = document.getElementById("output");
		if (!output) return;

		output.innerHTML += `<div>${e.data}</div>`;
	});
}

async function run() {
	const address = await websocketAddress();
	const ws = await connecting(address);
	done(ws);
}

run().catch(console.error);
