// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use consensus_types::safety_data::SafetyData;
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    hash::HashValue,
};
use libra_types::transaction::Transaction;
use serde::{Deserialize, Serialize, Serializer, Deserializer, de};
use base64;

fn to_base64<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
{
    serializer.serialize_str(&base64::encode(bytes))
}

fn from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de>
{
    let s = String::deserialize(deserializer)?;
    base64::decode(s).map_err(de::Error::custom)
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Value {
    #[serde(serialize_with = "to_base64", deserialize_with = "from_base64")]
    Bytes(Vec<u8>),
    Ed25519PrivateKey(Ed25519PrivateKey),
    Ed25519PublicKey(Ed25519PublicKey),
    HashValue(HashValue),
    String(String),
    Transaction(Transaction),
    U64(u64),
    SafetyData(SafetyData),
}

impl Value {
    pub fn bytes(self) -> Result<Vec<u8>, Error> {
        if let Value::Bytes(value) = self {
            Ok(value)
        } else {
            Err(Error::UnexpectedValueType)
        }
    }

    pub fn ed25519_private_key(self) -> Result<Ed25519PrivateKey, Error> {
        if let Value::Ed25519PrivateKey(value) = self {
            Ok(value)
        } else {
            Err(Error::UnexpectedValueType)
        }
    }

    pub fn ed25519_public_key(self) -> Result<Ed25519PublicKey, Error> {
        if let Value::Ed25519PublicKey(value) = self {
            Ok(value)
        } else {
            Err(Error::UnexpectedValueType)
        }
    }

    pub fn hash_value(self) -> Result<HashValue, Error> {
        if let Value::HashValue(value) = self {
            Ok(value)
        } else {
            Err(Error::UnexpectedValueType)
        }
    }

    pub fn string(self) -> Result<String, Error> {
        if let Value::String(value) = self {
            Ok(value)
        } else {
            Err(Error::UnexpectedValueType)
        }
    }

    pub fn u64(self) -> Result<u64, Error> {
        if let Value::U64(value) = self {
            Ok(value)
        } else {
            Err(Error::UnexpectedValueType)
        }
    }

    pub fn transaction(self) -> Result<Transaction, Error> {
        if let Value::Transaction(value) = self {
            Ok(value)
        } else {
            Err(Error::UnexpectedValueType)
        }
    }

    pub fn safety_data(self) -> Result<SafetyData, Error> {
        if let Value::SafetyData(value) = self {
            Ok(value)
        } else {
            Err(Error::UnexpectedValueType)
        }
    }
}
