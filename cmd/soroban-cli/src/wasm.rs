use clap::arg;
use sha2::{Digest, Sha256};
use soroban_env_host::xdr::{self, Hash, LedgerKey, LedgerKeyContractCode};
use soroban_spec_tools::contract::{self, Spec};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::utils::{self};
use std::borrow::Cow;
use std::io::Cursor;
use stellar_xdr::curr::{Limited, Limits, ReadXdr, ScMetaEntry, WriteXdr};
use wasm_encoder::{CustomSection, Section};
use wasmparser::{Parser as WasmParser, Payload};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("reading file {filepath}: {error}")]
    CannotReadContractFile {
        filepath: std::path::PathBuf,
        error: io::Error,
    },
    #[error("cannot parse wasm file {file}: {error}")]
    CannotParseWasm {
        file: std::path::PathBuf,
        error: wasmparser::BinaryReaderError,
    },
    #[error("xdr processing error: {0}")]
    Xdr(#[from] xdr::Error),

    #[error(transparent)]
    Parser(#[from] wasmparser::BinaryReaderError),
    #[error(transparent)]
    ContractSpec(#[from] contract::Error),
}

#[derive(Debug, clap::Args, Clone)]
#[group(skip)]
pub struct Args {
    /// Path to wasm binary
    #[arg(long)]
    pub wasm: PathBuf,
}

impl Args {
    /// # Errors
    /// May fail to read wasm file
    pub fn read(&self) -> Result<Vec<u8>, Error> {
        fs::read(&self.wasm).map_err(|e| Error::CannotReadContractFile {
            filepath: self.wasm.clone(),
            error: e,
        })
    }

    /// # Errors
    /// May fail to read wasm file
    pub fn len(&self) -> Result<u64, Error> {
        len(&self.wasm)
    }

    /// # Errors
    /// May fail to read wasm file
    pub fn is_empty(&self) -> Result<bool, Error> {
        self.len().map(|len| len == 0)
    }

    /// # Errors
    /// May fail to read wasm file or parse xdr section
    pub fn parse(&self) -> Result<Spec, Error> {
        let contents = self.read()?;
        Ok(Spec::new(&contents)?)
    }

    pub fn hash(&self) -> Result<Hash, Error> {
        Ok(Hash(Sha256::digest(self.read()?).into()))
    }

    pub fn read_contract_metadata(&self) -> Result<Vec<ScMetaEntry>, Error> {
        let buf = self.read()?;
        let mut meta = vec![];
        for payload in WasmParser::new(0).parse_all(&buf) {
            match payload? {
                Payload::CustomSection(s) => match s.name() {
                    "contractmetav0" => {
                        if !s.data().is_empty() {
                            let cursor = Cursor::new(s.data());
                            let data = ScMetaEntry::read_xdr_iter(&mut Limited::new(
                                cursor,
                                Limits::none(),
                            ))
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(Error::Xdr)?;
                            meta = data;
                        }
                    }
                    _ => {}
                },
                _other => {}
            }
        }
        Ok(meta)
    }

    pub fn update_customsection_metadata(&self, meta_entry: ScMetaEntry) -> Result<Vec<u8>, Error> {
        let mut metadata = self.read_contract_metadata()?;

        metadata.push(meta_entry);

        let mut cursor = Limited::new(Cursor::new(vec![]), Limits::none());
        metadata
            .iter()
            .for_each(|data| data.write_xdr(&mut cursor).unwrap());
        let metadata_xdr = cursor.inner.into_inner();

        let custom_section = CustomSection {
            name: Cow::from("contractmetav0"),
            data: Cow::from(metadata_xdr),
        };

        let mut wasm = self.read_contract_without_metadata()?;
        custom_section.append_to(&mut wasm);
        Ok(wasm)
    }

    fn read_contract_without_metadata(&self) -> Result<Vec<u8>, Error> {
        let buf = self.read()?;
        let buf_len = buf.len();
        let mut module = Vec::with_capacity(buf_len);

        for payload in WasmParser::new(0).parse_all(&buf) {
            let payload = payload?;
            match payload {
                Payload::CustomSection(s) => match s.name() {
                    "contractmetav0" => {
                        let range = s.range();
                        let section_header_size = calc_section_header_size(&range);

                        assert!(range.start >= section_header_size);
                        if range.start > 0 {
                            module.extend_from_slice(&buf[0..(range.start - section_header_size)]);
                        }
                        if range.end < buf_len {
                            module.extend_from_slice(&buf[range.end..buf_len]);
                        }
                    }
                    _ => {}
                },
                _other => {}
            }
        }
        module.shrink_to_fit();
        Ok(module)
    }
}

impl From<&PathBuf> for Args {
    fn from(wasm: &PathBuf) -> Self {
        Self { wasm: wasm.clone() }
    }
}

impl TryInto<LedgerKey> for Args {
    type Error = Error;
    fn try_into(self) -> Result<LedgerKey, Self::Error> {
        Ok(LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: utils::contract_hash(&self.read()?)?,
        }))
    }
}

/// # Errors
/// May fail to read wasm file
pub fn len(p: &Path) -> Result<u64, Error> {
    Ok(std::fs::metadata(p)
        .map_err(|e| Error::CannotReadContractFile {
            filepath: p.to_path_buf(),
            error: e,
        })?
        .len())
}

fn calc_section_header_size(range: &std::ops::Range<usize>) -> usize {
    let len = range.end - range.start;
    let mut buf = Vec::new();
    let int_enc_size = leb128::write::unsigned(&mut buf, len as u64);
    let int_enc_size = int_enc_size.expect("leb128 write");
    let section_id_byte = 1;
    int_enc_size + section_id_byte
}
