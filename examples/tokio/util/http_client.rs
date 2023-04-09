use super::ClientId;
use hyper::client::HttpConnector;
use hyper::{Body, Client, Request};

struct ServerConnection {
    url: String,
    client_id: Option<ClientId>,
}

impl ServerConnection {
    pub fn new(url: String) -> Self {
        Self {
            url,
            client_id: None,
        }
    }
    pub async fn allocate(&mut self, offer: String) -> anyhow::Result<(String)> {
        let client = Client::new();
        let request = Request::builder()
            .method("POST")
            .uri(self.url.clone())
            .body(Body::empty())?;

        // Send the request and await the response
        let response = client.request(request).await?;

        // Extract the response body
        let body = hyper::body::to_bytes(response.into_body()).await?;
        Ok("".into())
    }
    pub async fn free(&mut self) -> anyhow::Result<()> {
        if self.client_id.is_none() {
            return Ok(());
        }
        Ok(())
    }
}

impl Drop for ServerConnection {
    fn drop(&mut self) {
        self.free();
    }
}
