import { defineConfig } from "@neon/config/v1";

// Neon refreshes its own variables on checkout but retains application vars.
// Never upload the previous branch's OAuth client/resource to another branch.
if (process.env.MORTISE_OIDC_RESOURCE && process.env.NEON_FUNCTION_ACCOUNTS_BASE_URL &&
    process.env.MORTISE_OIDC_RESOURCE !== process.env.NEON_FUNCTION_ACCOUNTS_BASE_URL.replace(/\/$/, "")) {
  throw new Error("OAuth configuration belongs to another branch. Run scripts/configure-neon-auth.mjs with the current .env.local before deploying.");
}

export default defineConfig({
  // Declare your Neon services here
  auth: true,
  functions: {
    accounts: {
      name: "Mortise accounts",
      source: "./dist/accounts",
      bundler: "none",
      env: Object.fromEntries(
        ["MORTISE_OIDC_CLIENT_ID", "MORTISE_OIDC_CALLBACK_PORT", "MORTISE_OIDC_RESOURCE"]
          .filter((key) => process.env[key] !== undefined)
          .map((key) => [key, process.env[key]!]),
      ),
    },
  },
  // Branch policy: per-branch tuning
  branch: (branch) => {
    if (branch.isDefault) {
      // Default branch: no overrides, uses project defaults
      return {};
    }
    if (!branch.exists) {
      // New non-default branches: auto-expire
      // Run `neon checkout <name>` to create a new branch with these settings
      return { ttl: "7d" };
    }
    // Existing branch: no changes
    return {};
  },
});
