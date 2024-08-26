//! # bike-scan
//! Bke-Scan wird zum Scannen von IPsec Servern verwendet.
//! Die Funktion scan() ist für IkeV1 zuständig,
//! die Funktion scan_v2() ist für IkeV2 zuständig.
//! Die Funktionen verwenden Structs und Implementationen
//! der jeweigen Module.
//! Module für die scan()-Funktion: ike.rs, parse_ike.rs
//! Module für die scan_v2()-Funktion: ikev2.rs, parse_ikev2.rs

#![warn(missing_docs, clippy::expect_used, clippy::unwrap_used)]

use std::io;
use std::net::SocketAddr;
use std::time;

use rand::Rng;
use tokio::net::UdpSocket;
use zerocopy::network_endian::U16;
use zerocopy::network_endian::U32;
use zerocopy::network_endian::U64;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::default_ikev2_scan::DefaultIkeV2;
use crate::ike::ExchangeType;
use crate::ike::IkeV1;
use crate::ike::IkeV1Header;
use crate::ike::PayloadTypeV1;
use crate::ike::PayloadTypeV1::NoNextPayload;
use crate::ike::PayloadTypeV1::SecurityAssociation;
use crate::ike::ProposalPayload;
use crate::ike::SecurityAssociationV1;
use crate::ike_aggressive::IDPayload;
use crate::ike_aggressive::IdType::IpV4Addr;
use crate::ike_aggressive::IdType::UserFqdn;
use crate::ike_aggressive::IkeAggressive;
use crate::ike_aggressive::KeyExchangePayloadV1;
use crate::ikev2::testversion::TestIkeVersion;
use crate::ikev2::AttributeType;
use crate::ikev2::AttributeV2;
use crate::ikev2::ExchangeTypeV2;
use crate::ikev2::IkeV2;
use crate::ikev2::IkeV2Header;
use crate::ikev2::KeyExchangePayloadV2;
use crate::ikev2::NoncePayloadV2;
use crate::ikev2::PayloadTypeV2;
use crate::ikev2::Proposal;
use crate::ikev2::ProtocolId;
use crate::ikev2::SecurityAssociationV2;
use crate::ikev2::TransformAttributeV2;
use crate::ikev2::TransformTypeValues;
use crate::ikev2::TransformV2;
use crate::parse_ike::NotifyPacketV1;
use crate::parse_ike::ResponsePacket;
use crate::parse_ikev2::NotifyPacket;
use crate::parse_ikev2::ResponsePacketV2;

pub mod default_ikev2_scan;
pub mod ike;
pub mod ike_aggressive;
pub mod ikev2;
pub mod parse_ike;
pub mod parse_ikev2;

/*pub async fn full_scan() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
    let remote_addr = "ip:500".parse::<SocketAddr>().unwrap();
    socket.connect(remote_addr).await?;

    Ok(())
}*/
///Diese Funktion generiert das IkeV1 Paket und sendet diese an der Zielserver.
/// Wenn keine Transformationen gefunden werden,
/// wird das IkeV2 Paket mit der Funktion scan_v2 an den Server gesendet.
/// Die Antworten des Servers werden für IkeV1 verarbeitet.
pub async fn scan() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
    let remote_addr = "ip:500".parse::<SocketAddr>().unwrap();
    socket.connect(remote_addr).await?;
    //sending IKE Version 1 packet
    let transforms = IkeV1::build_transforms();
    for chunk in transforms.chunks(1) {
        //transforms.chunks(255) {
        //calculate random Initiator Security Parameter Index
        let initiator_spi: u64 = rand::thread_rng().gen();
        //Ike Version 1 Packet
        let mut ike_v1 = IkeV1 {
            header: IkeV1Header {
                initiator_spi: U64::from(initiator_spi),
                responder_spi: 0,
                next_payload: u8::from(SecurityAssociation),
                version: 16,
                exchange_type: 2,
                flag: 0,
                message_id: 0,
                length: Default::default(),
            },
            security_association_payload: SecurityAssociationV1 {
                sa_next_payload: u8::from(NoNextPayload),
                reserved: 0,
                sa_length: Default::default(),
                sa_doi: U32::from(1),
                sa_situation: U32::from(1),
            },
            proposal_payload: ProposalPayload {
                next_payload: u8::from(NoNextPayload),
                reserved: 0,
                length: Default::default(),
                proposal: 1,
                protocol_id: 1,
                spi_size: 0,
                number_of_transforms: Default::default(),
            },
            transform: vec![],
        };
        ike_v1.set_transforms(chunk);
        ike_v1.calculate_length();
        let bytes = ike_v1.convert_to_bytes();
        println!("Sende Paket");

        socket.send(&bytes).await.expect("Couldn't send packet");

        let mut buf = [0u8; 112];
        socket
            .recv_from(&mut buf)
            .await
            .expect("couldn't read buffer");

        let byte_slice = buf.as_slice();

        //parse Ike Response
        let ike_response = ResponsePacket::read_from_prefix(byte_slice).expect("Slice too short");
        ike_response.parse_response();
        if ike_response.header.next_payload == 11 {
            let notify_response =
                NotifyPacketV1::parse_notify(byte_slice).expect("parsing not possible");
            println!(
                "Error: {:?}",
                notify_response.notify_payload.notify_message_type
            )
        }
        let seconds = time::Duration::from_secs(10);
        tokio::time::sleep(seconds).await;
    }
    Ok(())
}

///aggressive mode
pub async fn scan_aggr() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
    let remote_addr = "ip:500".parse::<SocketAddr>().unwrap();
    socket.connect(remote_addr).await?;

    //Ike Aggressive Packet
    let transforms = IkeAggressive::build_transforms();
    for chunks in transforms.chunks(1) {
        let initiator_spi: u64 = rand::thread_rng().gen();
        let mut ike_aggr = IkeAggressive {
            header: IkeV1Header {
                initiator_spi: U64::from(initiator_spi),
                responder_spi: 0,
                next_payload: u8::from(PayloadTypeV1::SecurityAssociation),
                version: 16,
                exchange_type: 4,
                flag: 0,
                message_id: 0,
                length: Default::default(),
            },
            security_association_aggressive: SecurityAssociationV1 {
                sa_next_payload: u8::from(PayloadTypeV1::KeyExchange),
                reserved: 0,
                sa_length: Default::default(),
                sa_doi: U32::from(1),
                sa_situation: U32::from(1),
            },
            proposal_payload: ProposalPayload {
                next_payload: u8::from(NoNextPayload),
                reserved: 0,
                length: Default::default(),
                proposal: 1,
                protocol_id: 1,
                spi_size: 0,
                number_of_transforms: Default::default(),
            },
            transform: vec![],
            key_exchange_payload_v1: KeyExchangePayloadV1 {
                next_payload: u8::from(PayloadTypeV1::Nonce),
                reserved: 0,
                length: Default::default(),
            },
            key_exchange_data: vec![],
            nonce_payload: NoncePayloadV2 {
                next_payload_: u8::from(PayloadTypeV1::Identification),
                reserved: 0,
                length: Default::default(),
            },
            nonce_data: vec![],
            identification_payload: IDPayload {
                next_payload: u8::from(PayloadTypeV1::NoNextPayload),
                reserved: 0,
                length: Default::default(),
                id_ype: u8::from(UserFqdn),
                protocol_id: 0,
                port: U16::from(500),
                data: Default::default(),
            },
            //id_payload_data: vec![],
        };
        ike_aggr.set_transforms(chunks);
        ike_aggr.create_key_exchange_data();
        ike_aggr.generate_nonce();
        ike_aggr.id_data();
        ike_aggr.calculate_length();
        let bytes = ike_aggr.convert_to_bytes();
        println!("sende Paket");

        socket.send(&bytes).await.expect("Couldn't send packet");

        let mut buf = [0u8; 300];
        socket
            .recv_from(&mut buf)
            .await
            .expect("Couldn't read buffer");

        let byte_slice = buf.as_slice();
    }

    Ok(())
}

///Es wird das Paket für Ikev2 generiert und an den Server gesendet.
/// Die Antwort des Servers wird verarbeitet und in der Konsole ausgegeben
pub async fn scan_v2() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
    let remote_addr = ":500".parse::<SocketAddr>().unwrap();
    socket.connect(remote_addr).await?;
    //sending IKE Version 2 Packet
    let transforms_v2 = IkeV2::build_transforms_v2();
    for encryption_chunk in transforms_v2.0.chunks(63) {
        for prf_chunk in transforms_v2.1.chunks(63) {
            for integrity_algorithm_chunk in transforms_v2.2.chunks(63) {
                for diffie_group_chunk in transforms_v2.3.chunks(63) {
                    for key_exchange_diffie_group in (1u16..=2).chain(5..=5).chain(14..=18) {
                        let initiator_spi_v2: u64 = rand::thread_rng().gen();
                        let mut ike_v2 = IkeV2 {
                            header: IkeV2Header {
                                initiator_spi: U64::from(initiator_spi_v2),
                                responder_spi: U64::from(0),
                                next_payload: u8::from(PayloadTypeV2::SecurityAssociation),
                                version: 32,
                                exchange_type: u8::from(ExchangeTypeV2::IkeSaInit),
                                flag: 8,
                                message_id: 0,
                                length: Default::default(),
                            },
                            sa_payload_v2: SecurityAssociationV2 {
                                sa2_next_payload: u8::from(PayloadTypeV2::KeyExchange),
                                critical_bit: 0,
                                sa2_length: Default::default(),
                            },
                            proposal_v2: Proposal {
                                next_proposal: 0,
                                reserved: 0,
                                length: Default::default(),
                                proposal_number: 1,
                                protocol_id: ProtocolId::IKE,
                                spi_size: 0,
                                number_of_transforms: Default::default(),
                            },
                            encryption_transforms: vec![],
                            prf_transform: vec![],
                            integrity_algorithm_transform: vec![],
                            diffie_transform: vec![],
                            key_exchange: KeyExchangePayloadV2 {
                                next_payload: u8::from(PayloadTypeV2::Nonce),
                                reserved: 0,
                                length: Default::default(),
                                diffie_hellman_group: U16::from(key_exchange_diffie_group),
                                reserved2: Default::default(),
                            },
                            key_exchange_data: vec![],
                            nonce_payload: NoncePayloadV2 {
                                next_payload_: 0,
                                reserved: 0,
                                length: Default::default(),
                            },
                            nonce_data: vec![],
                        };
                        ike_v2.set_transforms_v2(
                            encryption_chunk,
                            prf_chunk,
                            integrity_algorithm_chunk,
                            diffie_group_chunk,
                        );
                        ike_v2.generate_key_exchange_data();
                        ike_v2.generate_nonce_data();
                        ike_v2.calculate_length_v2();

                        let bytes_v2 = ike_v2.convert_to_bytes_v2();
                        socket.send(&bytes_v2).await.expect("Couldn't send packet");

                        let mut buf_v2 = [0u8; 285];
                        socket
                            .recv_from(&mut buf_v2)
                            .await
                            .expect("couldn't read buffer");
                        let byte_slice_v2 = buf_v2.as_slice();
                        let ike_v2_response =
                            ResponsePacketV2::parse_ike_v2(byte_slice_v2).unwrap();
                        println!("{:?}", ike_v2_response);

                        println!(
                            "Ike Version is {:?}, ExchangeType is {:?}",
                            ike_v2_response.header.version, ike_v2_response.header.exchange_type
                        );

                        /*println!("Found Transforms: Encryption Algorthm: {:?}, Prf-Funktion: {:?}, Integrity Algorithm: {:?}, Diffie-Hellamn-Gruppe: {:?}"
                        ,ike_v2_response.encryption_transform.transform_id, ike_v2_response.prf_transform.transform_id, ike_v2_response.integrity_algorithm_transform.transform_id,
                        ike_v2_response.diffie_transform.transform_id);*/

                        if ike_v2_response.header.next_payload == 41 {
                            let notify_response =
                                NotifyPacket::parse_notify(byte_slice_v2).unwrap();
                            println!("Notify Payload: {:?}", notify_response);
                            if notify_response.notify_payload.notify_message_type.get() == 14 {
                                println!(
                                    "Notify Message: Error Code {:?}, no valid transforms",
                                    notify_response.notify_payload.notify_message_type
                                )
                            } else if notify_response.notify_payload.notify_message_type.get() == 17
                            {
                                println!(
                                    "Notify Message: Error Code {:?}, invalid key exchange data",
                                    notify_response.notify_payload.notify_message_type
                                )
                            } else {
                                println!(
                                    "Fehlercode: {:?}",
                                    notify_response.notify_payload.notify_message_type
                                )
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub async fn default_ike_v2_scan() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
    let remote_addr = "ip:500".parse::<SocketAddr>().unwrap();
    socket.connect(remote_addr).await?;
    let transforms_v2 = DefaultIkeV2::build_transforms_v2();
    for encryption_chunk in transforms_v2.0.chunks(1) {
        for prf_chunk in transforms_v2.1.chunks(1) {
            for integrity_algorithm_chunk in transforms_v2.2.chunks(1) {
                for diffie_group_chunk in transforms_v2.3.chunks(1) {
                    for key_exchange_diffie_group in (1u16..=2).chain(5..=5).chain(14..=18) {
                        let initiator_spi_v2: u64 = rand::thread_rng().gen();
                        let mut default_ike_v2 = IkeV2 {
                            header: IkeV2Header {
                                initiator_spi: U64::from(initiator_spi_v2),
                                responder_spi: U64::from(0),
                                next_payload: u8::from(PayloadTypeV2::SecurityAssociation),
                                version: 32,
                                exchange_type: u8::from(ExchangeTypeV2::IkeSaInit),
                                flag: 8,
                                message_id: 0,
                                length: Default::default(),
                            },
                            sa_payload_v2: SecurityAssociationV2 {
                                sa2_next_payload: u8::from(PayloadTypeV2::KeyExchange),
                                critical_bit: 0,
                                sa2_length: Default::default(),
                            },
                            proposal_v2: Proposal {
                                next_proposal: 0,
                                reserved: 0,
                                length: Default::default(),
                                proposal_number: 1,
                                protocol_id: ProtocolId::IKE,
                                spi_size: 0,
                                number_of_transforms: Default::default(),
                            },
                            encryption_transforms: vec![],
                            prf_transform: vec![],
                            integrity_algorithm_transform: vec![],
                            diffie_transform: vec![],
                            key_exchange: KeyExchangePayloadV2 {
                                next_payload: u8::from(PayloadTypeV2::Nonce),
                                reserved: 0,
                                length: Default::default(),
                                diffie_hellman_group: U16::from(key_exchange_diffie_group),
                                reserved2: Default::default(),
                            },
                            key_exchange_data: vec![],
                            nonce_payload: NoncePayloadV2 {
                                next_payload_: 0,
                                reserved: 0,
                                length: Default::default(),
                            },
                            nonce_data: vec![],
                        };
                        default_ike_v2.set_transforms_v2(
                            encryption_chunk,
                            prf_chunk,
                            integrity_algorithm_chunk,
                            diffie_group_chunk,
                        );
                        default_ike_v2.generate_key_exchange_data();
                        default_ike_v2.generate_nonce_data();
                        default_ike_v2.calculate_length_v2();

                        let bytes_v2 = default_ike_v2.convert_to_bytes_v2();
                        socket.send(&bytes_v2).await.expect("Couldn't send packet");

                        let mut buf_v2 = [0u8; 285];
                        socket
                            .recv_from(&mut buf_v2)
                            .await
                            .expect("couldn't read buffer");
                        let byte_slice_v2 = buf_v2.as_slice();
                        let ike_v2_response =
                            ResponsePacketV2::parse_ike_v2(byte_slice_v2).unwrap();
                        //println!("{:?}", ike_v2_response);

                        println!(
                            "Ike Version is {:?}, ExchangeType is {:?}",
                            ike_v2_response.header.version, ike_v2_response.header.exchange_type
                        );

                        println!("Found Transforms: Encryption Algorithm: {:?}, Prf-Funktion: {:?}, Integrity Algorithm: {:?}, Diffie-Hellamn-Gruppe: {:?}"
                                 ,ike_v2_response.encryption_transform.transform_id, ike_v2_response.prf_transform.transform_id, ike_v2_response.integrity_algorithm_transform.transform_id,
                                 ike_v2_response.diffie_transform.transform_id);

                        if ike_v2_response.header.next_payload == 41 {
                            let notify_response =
                                NotifyPacket::parse_notify(byte_slice_v2).unwrap();
                            if notify_response.notify_payload.notify_message_type.get() == 14 {
                                println!(
                                    "Notify Message: Error Code {:?}, no valid transforms",
                                    notify_response.notify_payload.notify_message_type
                                )
                            } else if notify_response.notify_payload.notify_message_type.get() == 17
                            {
                                println!(
                                    "Notify Message: Error Code {:?}, invalid key exchange data",
                                    notify_response.notify_payload.notify_message_type
                                )
                            }
                        }
                        let seconds = time::Duration::from_secs(20);
                        tokio::time::sleep(seconds).await;
                    }
                }
            }
        }
    }

    Ok(())
}
