//! The broker session.

use std::time::Duration;

use rumqttc::{AsyncClient, Event, LastWill, MqttOptions, Packet, QoS};
use tokio::sync::mpsc;

use crate::config::MqttConfig;

/// Something from the broker.
#[derive(Debug)]
pub enum Incoming {
    /// (Re)connected: subscriptions and retained state are sent again.
    Connected,
    /// A message on a subscribed topic.
    Message {
        /// The topic.
        topic: String,
        /// The payload.
        payload: Vec<u8>,
    },
}

/// The publishing half.
#[derive(Clone)]
pub struct Mqtt {
    client: AsyncClient,
}

/// The availability topic.
pub fn state_topic(base: &str) -> String {
    format!("{base}/bridge/state")
}

/// Connects (in the background) and returns the publisher and incoming messages.
pub fn connect(config: &MqttConfig) -> Result<(Mqtt, mpsc::Receiver<Incoming>), String> {
    let mut options = MqttOptions::new(&config.client_id, &config.host, config.port);
    options.set_keep_alive(Duration::from_secs(config.keepalive.max(5)));
    options.set_clean_session(true);
    options.set_max_packet_size(256 * 1024, 256 * 1024);
    options.set_last_will(LastWill::new(
        state_topic(&config.base_topic),
        crate::api::BridgeState::payload(crate::api::Availability::Offline),
        QoS::AtLeastOnce,
        true,
    ));
    if let Some(user) = &config.username {
        let password = match &config.password_file {
            Some(path) => std::fs::read_to_string(path)
                .map_err(|e| format!("mqtt.password_file {}: {e}", path.display()))?
                .trim_end()
                .to_string(),
            None => String::new(),
        };
        options.set_credentials(user, password);
    }
    let (client, mut event_loop) = AsyncClient::new(options, 1024);
    let (tx, rx) = mpsc::channel(256);
    tokio::spawn(async move {
        loop {
            match event_loop.poll().await {
                Ok(Event::Incoming(Packet::ConnAck(_))) => {
                    tracing::info!("MQTT connected");
                    if tx.send(Incoming::Connected).await.is_err() {
                        return;
                    }
                }
                Ok(Event::Incoming(Packet::Publish(p))) => {
                    let m = Incoming::Message {
                        topic: p.topic.clone(),
                        payload: p.payload.to_vec(),
                    };
                    if tx.send(m).await.is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "MQTT connection; retrying");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    });
    Ok((Mqtt { client }, rx))
}

impl Mqtt {
    /// Publishes; a full queue drops the message rather than stall the radio.
    pub fn publish(&self, topic: impl Into<String>, payload: impl Into<Vec<u8>>, retain: bool) {
        let topic = topic.into();
        if let Err(e) =
            self.client
                .try_publish(topic.clone(), QoS::AtMostOnce, retain, payload.into())
        {
            tracing::debug!(%topic, error = %e, "MQTT publish dropped");
        }
    }

    /// Publishes reliably (QoS 1), waiting for room in the queue.
    pub async fn publish_reliable(
        &self,
        topic: impl Into<String>,
        payload: impl Into<Vec<u8>>,
        retain: bool,
    ) {
        let topic = topic.into();
        if let Err(e) = self
            .client
            .publish(topic.clone(), QoS::AtLeastOnce, retain, payload.into())
            .await
        {
            tracing::warn!(%topic, error = %e, "MQTT publish");
        }
    }

    /// Publishes one of the [`api`](crate::api) payloads as JSON.
    pub fn publish_json<T: serde::Serialize>(
        &self,
        topic: impl Into<String>,
        value: &T,
        retain: bool,
    ) {
        self.publish(topic, serde_json::to_vec(value).unwrap_or_default(), retain);
    }

    /// Publishes one of the [`api`](crate::api) payloads as JSON, reliably
    /// (QoS 1).
    pub async fn publish_reliable_json<T: serde::Serialize>(
        &self,
        topic: impl Into<String>,
        value: &T,
        retain: bool,
    ) {
        self.publish_reliable(topic, serde_json::to_vec(value).unwrap_or_default(), retain)
            .await;
    }

    /// Subscribes.
    pub async fn subscribe(&self, filter: &str) {
        if let Err(e) = self.client.subscribe(filter, QoS::AtLeastOnce).await {
            tracing::warn!(%filter, error = %e, "MQTT subscribe");
        }
    }

    /// Disconnects cleanly (the will is not sent).
    pub async fn disconnect(&self) {
        let _ = self.client.disconnect().await;
    }
}
