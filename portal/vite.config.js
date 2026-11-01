import { defineConfig } from 'vite';
export default defineConfig({
  build: { outDir: 'dist', target: 'es2022', assetsInlineLimit: 0 },
  server: { proxy: { '/api': 'http://127.0.0.1:3000', '/matrix': 'http://127.0.0.1:3000' } },
});
