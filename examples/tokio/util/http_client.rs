use super::ClientId;
use hyper::client::HttpConnector;
use hyper::{Body, Client, Request};
use str0m::change::{SdpAnswer, SdpOffer};
use tracing::info;
use url::Url;

pub struct ServerConnection {
    url: Url,
    client_id: Option<ClientId>,
}

impl ServerConnection {
    pub fn new(url: &str) -> anyhow::Result<Self> {
        Ok(Self {
            url: Url::parse(url)?,
            client_id: None,
        })
    }
    pub async fn allocate(&mut self, offer: SdpOffer) -> anyhow::Result<String> {
        let client = Client::new();
        let mut url = self.url.clone();
        url.set_path("allocate");
        let request = Request::builder()
            .method("POST")
            .uri(url.to_string())
            .body(Body::from(serde_json::to_vec(&offer)?))?;

        // Send the request and await the response
        let response = client.request(request).await?;

        self.client_id = Some(1);

        // Extract the response body
        let body = hyper::body::to_bytes(response.into_body()).await?;
        Ok("".into())
    }

    pub async fn free(&mut self) -> anyhow::Result<()> {
        if let Some(client_id) = self.client_id {
            free(self.url.clone(), client_id).await?;
        }
        Ok(())
    }
}

async fn free(url: Url, client_id: ClientId) -> anyhow::Result<()> {
    info!("drop3");
    let client = Client::new();
    let mut url = url.clone();
    url.set_path("free");
    let request = Request::builder()
        .method("POST")
        .uri(url.to_string())
        .body(Body::empty())?;

    let _response = client.request(request).await?;

    Ok(())
}

impl Drop for ServerConnection {
    fn drop(&mut self) {
        info!("drop1");
        if let Some(client_id) = self.client_id {
            info!("drop2");
            tokio::spawn(free(self.url.clone(), client_id));
        }
    }
}
