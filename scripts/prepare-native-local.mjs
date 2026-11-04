import { copyFile } from 'node:fs/promises';
const file = process.platform === 'darwin' ? 'libmortise_accounts_node.dylib' : process.platform === 'win32' ? 'mortise_accounts_node.dll' : 'libmortise_accounts_node.so';
await copyFile(`target/debug/${file}`, 'target/debug/mortise-accounts.node');
console.log('Prepared native account module for local testing.');
