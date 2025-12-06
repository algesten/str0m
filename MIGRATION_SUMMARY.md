# Rouille to Feather Migration Summary

This PR demonstrates how to migrate from Rouille to Feather in the str0m examples.

## Files Changed

1. **Cargo.toml** - Replaced `rouille` dependency with `feather` (v0.6.0)
2. **examples/http-post.rs** - Migrated to use Feather's middleware API
3. **examples/chat.rs** - Migrated with custom Middleware struct for closure capture
4. **deny.toml** - Updated to exclude `feather` instead of `rouille`
5. **FEATHER_MIGRATION.md** - Comprehensive migration guide with TLS workarounds

## Key Differences: Rouille vs Feather

### Server Initialization

**Before (Rouille):**
```rust
let certificate = include_bytes!("cer.pem").to_vec();
let private_key = include_bytes!("key.pem").to_vec();

let server = Server::new_ssl("0.0.0.0:3000", web_request, certificate, private_key)
    .expect("starting the web server");
server.run();
```

**After (Feather):**
```rust
let mut app = App::new();

app.get("/", middleware!(|_req, res, _ctx| {
    res.send_html(include_str!("http-post.html"));
    next!()
}));

app.listen("0.0.0.0:3000");
```

### Request Handling

**Before (Rouille):**
```rust
fn web_request(request: &Request) -> Response {
    if request.method() == "GET" {
        return Response::html(include_str!("http-post.html"));
    }
    
    let mut data = request.data().expect("body to be available");
    let offer: SdpOffer = serde_json::from_reader(&mut data).expect("serialized offer");
    
    // ... handle request ...
    
    Response::from_data("application/json", body)
}
```

**After (Feather):**
```rust
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
```

## Benefits of Migration

1. ✅ **Active Maintenance** - Feather is actively developed (Rouille is unmaintained)
2. ✅ **Modern API** - Cleaner middleware-based architecture
3. ✅ **Better Performance** - Lightweight coroutine runtime without async
4. ✅ **Built-in Features** - JSON handling, logging, state management
5. ✅ **Simple Code** - No async/await complexity

## Important Consideration: TLS/HTTPS

⚠️ **Critical**: Feather doesn't have built-in TLS support.

Since WebRTC requires HTTPS, you must use one of these approaches:

### Production Setup (Recommended):

Use a reverse proxy like Nginx or Caddy:

```nginx
# Nginx example
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```caddy
# Caddy example (auto-HTTPS with Let's Encrypt)
your-domain.com {
    reverse_proxy localhost:3000
}
```

### Development Setup:

- Test on localhost (some browsers allow WebRTC without HTTPS on localhost)
- Use reverse proxy with self-signed certificate
- Use browser flags to bypass HTTPS requirements (not recommended)

## Migration Patterns

### Pattern 1: Simple Middleware (http-post.rs)

Use the `middleware!` macro for simple handlers:

```rust
app.get("/", middleware!(|_req, res, _ctx| {
    res.send_html(include_str!("http-post.html"));
    next!()
}));
```

### Pattern 2: Capturing State (chat.rs)

For handlers that need to capture variables, implement a custom Middleware struct:

```rust
struct PostHandler {
    tx: SyncSender<Rtc>,
    addr: SocketAddr,
}

impl Middleware for PostHandler {
    fn handle(&self, request: &mut Request, response: &mut Response, _ctx: &AppContext) -> Outcome {
        // Access self.tx and self.addr here
        // ...
        next!()
    }
}

app.post("/", PostHandler { tx, addr });
```

### Pattern 3: JSON Handling

Feather's JSON API returns `serde_json::Value`, so you need a two-step process:

```rust
let json_value = req.json()?;
let offer: SdpOffer = serde_json::from_value(json_value)?;
```

## Testing the Migration

All examples compile successfully:

```bash
# Build all examples
cargo build --examples

# Run http-post example
cargo run --example http-post

# Run chat example
cargo run --example chat
```

## Next Steps

1. ✅ Migration is complete and compiles successfully
2. ✅ Documentation explains TLS workaround
3. 📋 Set up reverse proxy for production deployment
4. 📋 Test with actual WebRTC clients through HTTPS
5. 📋 Monitor Feather for future TLS support

## Questions?

See `FEATHER_MIGRATION.md` for detailed information about:
- TLS/HTTPS setup with reverse proxies
- Advanced middleware patterns
- Error handling
- Future considerations

## Conclusion

This migration successfully demonstrates how str0m examples can be adapted from Rouille to Feather. While Feather doesn't have built-in TLS, the reverse proxy approach is a standard, production-ready solution used by many web applications. The cleaner API and active maintenance make Feather a solid choice for the future.
