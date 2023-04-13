/**
ws-key-auth A simple WebSocket key authentication client
Copyright (C) 2023  Sal Rahman

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

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

async function sign(
	data: ArrayBuffer,
	keyPair: CryptoKeyPair
): Promise<ArrayBuffer> {
	const signature = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		keyPair.privateKey,
		data
	);
	return signature;
}

async function connecting(address: string) {
	a.innerHTML = "Connecting...";

	// Generate a random P-256 key pair
	const keyPair = await generateKeys();

	const clientId = await getClientId(keyPair);

	const ws = new WebSocket(address);

	await Promise.race([
		new Promise((_, reject) => {
			ws.addEventListener("error", () => {
				reject();
			});
		}),
		connect(ws, clientId, (data) => {
			return sign(data, keyPair);
		}),
	]);

	return ws;
}

async function done(ws: WebSocket) {
	a.innerHTML = `
		<p>Connected</p>
		<div><textarea id='input'></textarea><button id="submit">Submit</button></div>

		<div id="output">

		</div>
	`;

	const input = document.getElementById("input") as HTMLTextAreaElement;
	const submit = document.getElementById("submit");
	if (!input) throw new Error("DOM error");
	if (!submit) throw new Error("DOM error");

	submit.addEventListener("click", () => {
		ws.send(input.value);
	});

	ws.addEventListener("message", (e) => {
		const output = document.getElementById("output");
		if (!output) return;

		output.innerHTML += `<div>${e.data}</div>`;
	});
}

async function run() {
	const address = await websocketAddress();
	try {
		const ws = await connecting(address);
		if (!ws) throw new Error("Failed to connect");
		done(ws);
	} catch {
		a.innerHTML = "Failed to connect";
	}
}

run().catch(console.error);
