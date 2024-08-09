//! #Bike-Scan
//! Aggressive Mode

use std::fs;

use rand::random;
use zerocopy::network_endian::U16;
use zerocopy::network_endian::U32;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::ike::Attribute;
use crate::ike::AttributeType;
use crate::ike::IkeV1Header;
use crate::ike::PayloadTypeV1::Transform;
use crate::ike::ProposalPayload;
use crate::ike::SecurityAssociationV1;
use crate::ike::Transform as Transform_aggr;
use crate::ike::TransformPayload;
use crate::ikev2::NoncePayloadV2;

/// Wrapper Struct
#[derive(Debug, Clone)]
pub struct IkeAggressive {
    header: IkeV1Header,
    security_association_aggressive: SecurityAssociationV1,
    proposal_payload: ProposalPayload,
    key_exchange_payload_v1: KeyExchangePayloadV1,
    transform: Vec<Transform_aggr>,
    key_exchange_data: Vec<u8>,
    nonce_payload: NoncePayloadV2,
    nonce_data: Vec<u8>,
    identification_payload: IDPayload,
    id_payload_data: Vec<u8>,
}

impl IkeAggressive {
    /// create critical transforms
    pub fn build_transforms() -> Vec<Transform_aggr> {
        let mut transform_vec = vec![];
        let payload: u8 = u8::from(Transform);
        for encryption in (1..=8) {
            for hash in (1..=3) {
                for auth_method in 1..=3 {
                    for diffie_group in (1..=5).chain(14..=14) {
                        transform_vec.push(Transform_aggr {
                            transform_payload: TransformPayload {
                                next_payload: payload,
                                reserved: 0,
                                length: U16::from(36),
                                transform_number: 0,
                                transform_id: 1,
                                reserved2: U16::from(0),
                            },
                            encryption_attribute: Attribute {
                                attribute_type: U16::from(AttributeType::Encryption),
                                attribute_value_or_length: U16::from(encryption),
                            },
                            hash_attribute: Attribute {
                                attribute_type: U16::from(AttributeType::HashType),
                                attribute_value_or_length: U16::from(hash),
                            },
                            diffie_hellman_attribute: Attribute {
                                attribute_type: U16::from(AttributeType::DiffieHellmanGroup),
                                attribute_value_or_length: U16::from(diffie_group),
                            },
                            authentication_method_attribute: Attribute {
                                attribute_type: U16::from(AttributeType::AuthenticationMethod),
                                attribute_value_or_length: U16::from(auth_method),
                            },
                            life_type_attribute: Attribute {
                                attribute_type: U16::from(AttributeType::LifeType),
                                attribute_value_or_length: U16::from(1),
                            },
                            life_duration_attribute: Attribute {
                                attribute_type: U16::from(AttributeType::LifeDuration),
                                attribute_value_or_length: U16::from(4),
                            },
                            life_duration_value: U32::from(28800),
                        });
                    }
                }
            }
        }
        transform_vec
    }

    /// overflow protection for transforms
    pub fn set_transforms(&mut self, transforms: &[crate::ike::Transform]) {
        let length = transforms.len();
        let length_checked = u8::try_from(length).expect("Too many transforms");
        self.proposal_payload.number_of_transforms = length_checked;
        let mut change_transforms = Vec::from(transforms);
        for i in 0..length_checked {
            change_transforms[i as usize]
                .transform_payload
                .transform_number = i;
        }
        change_transforms[length - 1].transform_payload.next_payload = 0;
        self.transform = change_transforms
    }
    /// create key echange data
    pub fn create_key_exchange_data(&mut self) {}

    /// create nonce payload
    pub fn generate_nonce(&mut self) {
        let nonce_data: Vec<u8> = (0..174).map(|_| random::<u8>()).collect();
        self.nonce_data = nonce_data;
    }
    /// create id data
    pub fn id_data(&mut self) {
        let username = "admin@foo.bar.com";
        let ipv4 = "0.0.0.0";
        if self.identification_payload.id_ype == u8::from(IdType::IpV4Addr) {
            self.identification_payload.data = ipv4.parse().unwrap();
        } else if self.identification_payload.id_ype == u8::from(IdType::UserFqdn) {
            self.identification_payload.data = username.parse().unwrap()
        }
    }
    /// calculate length
    pub fn calculate_length(&mut self) {
        self.proposal_payload.length =
            U16::from(8 + (self.proposal_payload.number_of_transforms as u16) * 36);
        self.security_association_aggressive.sa_length =
            U16::from(self.proposal_payload.length) + U16::from(12);
        self.key_exchange_payload_v1.length = U16::from(4 + (self.key_exchange_data.len() as u16));
        self.nonce_payload.length = U16::from(4 + self.nonce_data.len() as u16);
        self.identification_payload.length = U16::from(8 + self.id_payload_data.len() as u16);
        self.header.length = U32::from(
            self.security_association_aggressive.sa_length
                + self.key_exchange_payload_v1.length
                + self.nonce_payload.length
                + self.identification_payload.length,
        );
    }
    /// convert to bytes
    pub fn convert_to_bytes(&mut self) -> Vec<u8> {
        let mut bytes_aggr = vec![];
        bytes_aggr.extend_from_slice(self.header.as_bytes());
        bytes_aggr.extend(self.security_association_aggressive.as_bytes());
        bytes_aggr.extend_from_slice(self.proposal_payload.as_bytes());
        bytes_aggr.extend_from_slice(self.transform.as_bytes());
        bytes_aggr.extend_from_slice(self.key_exchange_payload_v1.as_bytes());
        bytes_aggr.extend_from_slice(self.key_exchange_data.as_bytes());
        bytes_aggr.extend_from_slice(self.nonce_payload.as_bytes());
        bytes_aggr.extend_from_slice(self.nonce_data.as_bytes());
        bytes_aggr.extend_from_slice(self.identification_payload.as_bytes());
        bytes_aggr.extend_from_slice(self.id_payload_data.as_bytes());
        bytes_aggr
    }
}
///Identification Payload
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct IDPayload {
    next_payload: u8,
    reserved: u8,
    length: U16,
    id_ype: u8,
    protocol_id: u8,
    port: U16,
    data: u8, //placeholder
}
#[derive(Debug, Copy, Clone, AsBytes)]
#[repr(u8)]
pub enum IdType {
    ///username (user@foo.bar.com)
    UserFqdn,
    ///Ipv4 Address
    IpV4Addr,
}

impl From<IdType> for u8 {
    fn from(value: IdType) -> Self {
        match value {
            IdType::UserFqdn => 3,
            IdType::IpV4Addr => 1,
        }
    }
}

impl IdType {
    fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(IdType::IpV4Addr),
            3 => Some(IdType::UserFqdn),
            _ => None,
        }
    }
}
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(packed)]
pub struct KeyExchangePayloadV1 {
    next_payload: u8,
    reserved: u8,
    length: U16,
    data: u8, //placeholder (einfach diffie gruppen data, nur bis 2048 bit)
}
