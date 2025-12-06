# Migration from Rouille to Feather

This document explains the migration from Rouille to Feather web framework in the str0m examples.

## What Changed

The examples (`chat.rs` and `http-post.rs`) have been migrated from using Rouille to using Feather, a more modern and actively maintained Rust web framework.

### Key Changes:

1. **Dependency Update**: Replaced `rouille` with `feather` in `Cargo.toml`
2. **API Migration**: Updated HTTP server initialization and request handling to use Feather's API
3. **Middleware Pattern**: Adapted to Feather's middleware-first architecture

## Important: TLS/HTTPS Limitation

**⚠️ Critical Note**: Unlike Rouille which has built-in TLS support, Feather does not currently support TLS/HTTPS natively.

Since WebRTC **requires HTTPS** to function in web browsers (except for localhost in some browsers), you have the following options for production use:

### Option 1: Reverse Proxy (Recommended)

Use a reverse proxy like Nginx or Caddy to terminate TLS and forward requests to the Feather HTTP server.

**Example Nginx Configuration:**

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Example Caddy Configuration:**

```
your-domain.com {
    reverse_proxy localhost:3000
}
```

Caddy automatically handles TLS certificate provisioning via Let's Encrypt.

### Option 2: Manual TLS Integration

For advanced users, you can manually wrap the Feather server with `rustls` or `native-tls` by:

1. Creating a TLS listener
2. Accepting connections
3. Wrapping the stream with TLS
4. Forwarding requests to Feather's handler

This approach is more complex and requires modifications to the Feather runtime or creating a custom server implementation.

### Option 3: Development/Testing

For local development, you can:
- Use `localhost` which some browsers allow for WebRTC without HTTPS
- Use browser flags to bypass HTTPS requirements (not recommended for production)
- Use a self-signed certificate with a reverse proxy

## Code Changes Summary

### Before (Rouille):

```rust
use rouille::Server;
use rouille::{Request, Response};

let certificate = include_bytes!("cer.pem").to_vec();
let private_key = include_bytes!("key.pem").to_vec();

let server = Server::new_ssl("0.0.0.0:3000", web_request, certificate, private_key)
    .expect("starting the web server");
server.run();
```

### After (Feather):

```rust
use feather::{App, middleware, next};

let mut app = App::new();

app.get("/", middleware!(|_req, res, _ctx| {
    res.send_html(include_str!("http-post.html"));
    next!()
}));

app.post("/", middleware!(|req, res, _ctx| {
    let json_value = req.json()?;
    let offer: SdpOffer = serde_json::from_value(json_value)?;
    // ... handle request ...
    res.send_json(answer);
    next!()
}));

app.listen("0.0.0.0:3000");
```

## Benefits of Feather

Despite the TLS limitation, Feather offers several advantages:

1. **Active Development**: Feather is actively maintained (Rouille has been unmaintained)
2. **Modern API**: Cleaner, more ergonomic API with middleware-first design
3. **Better Performance**: Uses a lightweight coroutine-based runtime
4. **No Async Required**: Simpler synchronous code that's easier to reason about
5. **Built-in Features**: JSON support, logging, and more out of the box

## Migration Notes

- The examples now log a warning about TLS requirements on startup
- They provide example nginx configuration in the logs
- The HTTP endpoint is on port 3000 (same as before)
- All WebRTC logic remains unchanged
- For production deployments, ensure you use HTTPS via a reverse proxy

## Testing the Migration

To test locally:

```bash
# Start the example
cargo run --example http-post

# In another terminal, set up a reverse proxy with TLS
# OR test with localhost (some browsers allow WebRTC on localhost without HTTPS)
```

## Questions or Issues?

If you encounter issues with the migration or need help setting up TLS, please:
1. Check the Feather documentation: https://github.com/BersisSe/feather
2. Review the reverse proxy setup guides for Nginx/Caddy
3. Open an issue on the str0m repository

## Future Considerations

If Feather adds native TLS support in the future, the migration will be straightforward:
- Update the `app.listen()` call to include certificate configuration
- Remove the reverse proxy requirement from documentation
- Simplify deployment

Until then, the reverse proxy approach is the recommended solution for production deployments.
