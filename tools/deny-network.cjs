// The configuration validator and lock-only SBOM generation require no network.
// Deny every outbound socket, including model endpoints, before loading tools.
const deny = () => { throw new Error('TOOL_VALIDATION_NETWORK_FORBIDDEN'); };
require('node:net').Socket.prototype.connect = deny;
require('node:dns').lookup = deny;
globalThis.fetch = deny;
