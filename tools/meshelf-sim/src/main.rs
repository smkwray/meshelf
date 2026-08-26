use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use meshelf_core::{OfferDescriptor, OfferId, OfferSource, OfferSourceInput};
use meshelf_identity::InstallationIdentity;
use meshelf_net::{
    ExactDeviceAllowList, OfferAnnouncementHandler, OfferFetchHandler, PeerClient, ServerIdentity,
    V2OfferServices, serve_v2_with_offers_and_fetch,
};
use meshelf_protocol::{ClientHello, OfferAckCode, OfferAnnouncement};
use meshelf_store::RedbV2Store;
use tokio::{net::TcpListener, sync::watch};

#[tokio::main]
async fn main() -> Result<()> {
    let bmst_identity = InstallationIdentity::generate();
    let bzot_identity = InstallationIdentity::generate();
    let bmst = bmst_identity.device_id;
    let bzot = bzot_identity.device_id;
    let source_path =
        std::env::temp_dir().join(format!("meshelf-sim-source-{}.redb", OfferId::new()));
    let card_path = std::env::temp_dir().join(format!("meshelf-sim-card-{}.redb", OfferId::new()));
    let source_store = Arc::new(RedbV2Store::open(&source_path).context("open source store")?);
    let card_store = Arc::new(RedbV2Store::open(&card_path).context("open card store")?);
    let offer_id = OfferId::new();
    source_store.insert_offer_source(OfferSourceInput::new(
        offer_id,
        OfferDescriptor::text("meshelf loopback: α\nβ\n🙂")?,
        HashSet::from([bzot]),
        OfferSource::Text {
            text: "meshelf loopback: α\nβ\n🙂".to_owned(),
        },
    ))?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .context("bind loopback receiver")?;
    let address = listener.local_addr().context("read listener address")?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(serve_v2_with_offers_and_fetch(
        listener,
        ServerIdentity {
            signing_identity: bzot_identity.clone(),
            device_name: "BZOT".to_owned(),
        },
        Arc::new(ExactDeviceAllowList::new([bmst])),
        V2OfferServices {
            announcement_receiver: Arc::new(OfferAnnouncementHandler::new(card_store.clone())),
            fetch_sender: Arc::new(OfferFetchHandler::new(bmst, source_store)),
        },
        Duration::from_secs(2),
        shutdown_rx,
    ));
    let announcement = OfferAnnouncement::new(
        offer_id,
        bmst,
        bzot,
        1,
        OfferDescriptor::text("meshelf loopback: α\nβ\n🙂")?,
    );
    let client = PeerClient::with_timeouts(Duration::from_secs(2), Duration::from_secs(2));
    let first = client
        .announce_offer_v2(
            address,
            ClientHello::signed_v2(bmst, "BMST", "simulation-1", &bmst_identity),
            announcement.clone(),
            &bzot_identity.public_key(),
        )
        .await
        .context("first announcement")?;
    let duplicate = client
        .announce_offer_v2(
            address,
            ClientHello::signed_v2(bmst, "BMST", "simulation-2", &bmst_identity),
            announcement,
            &bzot_identity.public_key(),
        )
        .await
        .context("duplicate announcement")?;
    if first.code != OfferAckCode::Stored || duplicate.code != OfferAckCode::Duplicate {
        bail!(
            "simulation failed: first={:?}, duplicate={:?}",
            first.code,
            duplicate.code
        );
    }
    if card_store.read_offer_shelf()?.len() != 1 {
        bail!("simulation stored an unexpected number of cards");
    }
    shutdown_tx.send(true).context("request shutdown")?;
    server.await.context("join server")??;
    let _ = std::fs::remove_file(source_path);
    let _ = std::fs::remove_file(card_path);
    println!("PASS: direct protocol-2 announcement stored exactly one metadata card");
    Ok(())
}
