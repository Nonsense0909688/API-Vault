# API-Vault JavaScript SDK

Official JavaScript SDK for interacting with an API-Vault server.

## Installation

```bash
npm install @api-vault/sdk
````

## Usage

```js
const APIVault = require("@api-vault/sdk");

async function main() {
    const vault = new APIVault("http://localhost:8080");
    await vault.login("your-login-key");

    const secrets = await vault.getSecrets();
    console.log(secrets);

    await vault.logout();
}

main();
```

---

## API

### `new APIVault(baseUrl)`

Creates a new API-Vault client.

```js
const vault = new APIVault("http://localhost:8080");
```

| Parameter | Type     | Description                 |
| --------- | -------- | --------------------------- |
| `baseUrl` | `string` | URL of the API-Vault server |

---

### `vault.login(key)`

Authenticates with the API-Vault server and creates a session.

```js
await vault.login("your-login-key");
```

#### Parameters

| Parameter | Type     | Description         |
| --------- | -------- | ------------------- |
| `key`     | `string` | API-Vault login key |

---

### `vault.getSecrets()`

Retrieves the secrets available to the authenticated session.

```js
const secrets = await vault.getSecrets();

console.log(secrets);
```

This method requires an active session.

---

### `vault.logout()`

Terminates the current API-Vault session.

```js
await vault.logout();
```

---

## Complete Example

```js
const APIVault = require("@api-vault/sdk");

async function main() {
    const vault = new APIVault("http://localhost:8080");

    try {
        await vault.login("your-login-key");

        const secrets = await vault.getSecrets();
        console.log(secrets);
    } finally {
        await vault.logout();
    }
}

main();
```

Using `finally` ensures that the client attempts to logout even if an error occurs while accessing the vault.

---

## Security

Do not hard-code your API-Vault login key in source code.

Use environment variables instead:

```bash
API_VAULT_KEY=your-login-key
```

```js
const APIVault = require("@api-vault/sdk");

async function main() {
    const vault = new APIVault("http://localhost:8080");
    await vault.login(process.env.API_VAULT_KEY);

    const secrets = await vault.getSecrets();
    console.log(secrets);

    await vault.logout();
}

main();
```

> Keep your API-Vault credentials private and never commit them to a public repository.

## Requirements

* Node.js with `fetch` support
* A running API-Vault server
* Valid API-Vault credentials

## License
MIT
