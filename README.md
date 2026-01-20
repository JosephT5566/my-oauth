## Local test
Start the local
```
npx wrangler dev
```

## KV
Storing values in remote KV namespace ([doc](https://developers.cloudflare.com/kv/get-started/#4-interact-with-your-kv-namespace))

```
npx wrangler kv key put --namespace-id=xxxxxxxxxxxxxxxx "<KEY>" "<VALUE>" --remote
```

(Without `--remote`, it's just modifying local dev simulated resources)

### Key value pairs
The config keys are necessary for the proxy.
The key serves for the available entry and the following GAS url.

For example, key: `config:test-app`, and the url `/test/config/test-app/...` is available.
And the value should be:
```
{
  "allowed_origins": ["http://localhost:3000", "https://josephtseng-tw.github.io"],
  "gas_url": "<GAS_URL>"
}
```