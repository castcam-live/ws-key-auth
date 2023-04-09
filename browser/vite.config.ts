import { resolve } from "path";

export default {
	build: {
		lib: {
			entry: resolve(__dirname, "src/lib.ts"),
			name: "ws-key-auth",
			fileName: "ws-key-auth",
		},
	},
};
