import { defineConfig } from "vite";

export default defineConfig({
  base: "/public-vc-verifier/",
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
