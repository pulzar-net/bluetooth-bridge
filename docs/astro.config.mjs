// The bluetooth-bridge docs: Starlight with the shared Pulzar theme
// (github.com/pulzar-net/docs-theme). Pages are in src/content/docs; the
// configuration reference there is generated from the code
// (crates/bluetooth-bridge/tests/config_reference.rs). Built and published by
// .github/workflows/docs.yml, which adds the API docs under /api.
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { pulzarPlugins } from '@pulzr/docs-theme';
import sidebar from './sidebar.mjs';

export default defineConfig({
	site: 'https://pulzar-net.github.io',
	base: '/bluetooth-bridge',
	// Pages are page.html, the URLs the earlier mdBook site had.
	build: { format: 'file' },
	redirects: {
		'/library/index': '/bluetooth-bridge/library.html',
		// The crate was bluetooth-mesh before it was published.
		'/library/bluetooth-mesh': '/bluetooth-bridge/library/bluetooth-mesh-stack.html',
	},
	integrations: [
		starlight({
			title: 'bluetooth-bridge',
			description: 'A Bluetooth host stack on raw HCI and a Bluetooth LE to MQTT bridge in Rust.',
			plugins: pulzarPlugins({
				project: 'bluetooth-bridge',
				linkExclude: ['/bluetooth-bridge/api/**', '/bluetooth-bridge/config.schema.json'],
			}),
			sidebar,
		}),
	],
});
