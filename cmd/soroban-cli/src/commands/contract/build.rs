use clap::Parser;
use itertools::Itertools;
use std::{
    collections::HashSet,
    env,
    ffi::OsStr,
    fmt::Debug,
    fs, io,
    path::Path,
    process::{Command, ExitStatus, Stdio},
    str,
};

use cargo_metadata::{Metadata, MetadataCommand, Package};

use std::borrow::Cow;
use std::io::Cursor;
use std::str::FromStr;
use stellar_xdr::curr::{Limited, Limits, ReadXdr, ScMetaEntry, ScMetaV0, StringM, WriteXdr};
use wasm_encoder::{CustomSection, Section};
use wasmparser::{BinaryReaderError, Parser as WasmParser, Payload};

/// Build a contract from source
///
/// Builds all crates that are referenced by the cargo manifest (Cargo.toml)
/// that have cdylib as their crate-type. Crates are built for the wasm32
/// target. Unless configured otherwise, crates are built with their default
/// features and with their release profile.
///
/// To view the commands that will be executed, without executing them, use the
/// --print-commands-only option.
#[derive(Parser, Debug, Clone)]
pub struct Cmd {
    /// Path to Cargo.toml
    #[arg(long, default_value = "Cargo.toml")]
    pub manifest_path: std::path::PathBuf,
    /// Package to build
    ///
    /// If omitted, all packages that build for crate-type cdylib are built.
    #[arg(long)]
    pub package: Option<String>,
    /// Build with the specified profile
    #[arg(long, default_value = "release")]
    pub profile: String,
    /// Build with the list of features activated, space or comma separated
    #[arg(long, help_heading = "Features")]
    pub features: Option<String>,
    /// Build with the all features activated
    #[arg(
        long,
        conflicts_with = "features",
        conflicts_with = "no_default_features",
        help_heading = "Features"
    )]
    pub all_features: bool,
    /// Build with the default feature not activated
    #[arg(long, help_heading = "Features")]
    pub no_default_features: bool,
    /// Directory to copy wasm files to
    ///
    /// If provided, wasm files can be found in the cargo target directory, and
    /// the specified directory.
    ///
    /// If ommitted, wasm files are written only to the cargo target directory.
    #[arg(long)]
    pub out_dir: Option<std::path::PathBuf>,
    /// Print commands to build without executing them
    #[arg(long, conflicts_with = "out_dir", help_heading = "Other")]
    pub print_commands_only: bool,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Metadata(#[from] cargo_metadata::Error),
    #[error(transparent)]
    CargoCmd(io::Error),
    #[error(transparent)]
    GitCmd(io::Error),
    #[error("exit status {0}")]
    Exit(ExitStatus),
    #[error("package {package} not found")]
    PackageNotFound { package: String },
    #[error("creating out directory: {0}")]
    CreatingOutDir(io::Error),
    #[error("copying wasm file: {0}")]
    CopyingWasmFile(io::Error),
    #[error("reading wasm file: {0}")]
    ReadingWasmFile(io::Error),
    #[error("writing wasm file: {0}")]
    WritingWasmFile(io::Error),
    #[error("removing temp file: {0}")]
    RemoveTempFile(io::Error),
    #[error(transparent)]
    ParsingWasm(BinaryReaderError),
    #[error("getting the current directory: {0}")]
    GettingCurrentDir(io::Error),
    #[error(transparent)]
    Xdr(soroban_env_host::xdr::Error),
    #[error(transparent)]
    Utf8(std::str::Utf8Error),
}

impl Cmd {
    pub fn run(&self) -> Result<(), Error> {
        let working_dir = env::current_dir().map_err(Error::GettingCurrentDir)?;

        let metadata = self.metadata()?;
        let packages = self.packages(&metadata);
        let workspace_root = &metadata.workspace_root;
        let target_dir = &metadata.target_directory;

        let git_data = git_data(&metadata.workspace_root.as_str())?;

        if let Some(package) = &self.package {
            if packages.is_empty() {
                return Err(Error::PackageNotFound {
                    package: package.clone(),
                });
            }
        }

        for p in packages {
            let mut cmd = Command::new("cargo");
            cmd.stdout(Stdio::piped());

            cmd.arg("rustc");
            let manifest_path = pathdiff::diff_paths(&p.manifest_path, &working_dir)
                .unwrap_or(p.manifest_path.clone().into());
            cmd.arg(format!(
                "--manifest-path={}",
                manifest_path.to_string_lossy()
            ));
            cmd.arg("--crate-type=cdylib");
            cmd.arg("--target=wasm32-unknown-unknown");
            if self.profile == "release" {
                cmd.arg("--release");
            } else {
                cmd.arg(format!("--profile={}", self.profile));
            }
            if self.all_features {
                cmd.arg("--all-features");
            }
            if self.no_default_features {
                cmd.arg("--no-default-features");
            }
            if let Some(features) = self.features() {
                let requested: HashSet<String> = features.iter().cloned().collect();
                let available = p.features.iter().map(|f| f.0).cloned().collect();
                let activate = requested.intersection(&available).join(",");
                if !activate.is_empty() {
                    cmd.arg(format!("--features={activate}"));
                }
            }
            let cmd_str = format!(
                "cargo {}",
                cmd.get_args().map(OsStr::to_string_lossy).join(" ")
            );

            if self.print_commands_only {
                println!("{cmd_str}");
            } else {
                eprintln!("{cmd_str}");
                let status = cmd.status().map_err(Error::CargoCmd)?;
                if !status.success() {
                    return Err(Error::Exit(status));
                } else {
                    self.update_contractmeta_in_contract(
                        target_dir.as_str(),
                        workspace_root.as_str(),
                        &p,
                        &git_data,
                    )?;
                }

                if let Some(out_dir) = &self.out_dir {
                    fs::create_dir_all(out_dir).map_err(Error::CreatingOutDir)?;

                    let file = format!("{}.wasm", p.name.replace('-', "_"));
                    let target_file_path = Path::new(target_dir)
                        .join("wasm32-unknown-unknown")
                        .join(&self.profile)
                        .join(&file);
                    let out_file_path = Path::new(out_dir).join(&file);
                    fs::copy(target_file_path, out_file_path).map_err(Error::CopyingWasmFile)?;
                }
            }
        }

        Ok(())
    }

    fn features(&self) -> Option<Vec<String>> {
        self.features
            .as_ref()
            .map(|f| f.split(&[',', ' ']).map(String::from).collect())
    }

    fn packages(&self, metadata: &Metadata) -> Vec<Package> {
        metadata
            .packages
            .iter()
            .filter(|p|
                // Filter by the package name if one is provided.
                self.package.is_none() || Some(&p.name) == self.package.as_ref())
            .filter(|p| {
                // Filter crates by those that build to cdylib (wasm), unless a
                // package is provided.
                self.package.is_some()
                    || p.targets
                        .iter()
                        .any(|t| t.crate_types.iter().any(|c| c == "cdylib"))
            })
            .cloned()
            .collect()
    }

    fn metadata(&self) -> Result<Metadata, cargo_metadata::Error> {
        let mut cmd = MetadataCommand::new();
        cmd.no_deps();
        cmd.manifest_path(&self.manifest_path);
        // Do not configure features on the metadata command, because we are
        // only collecting non-dependency metadata, features have no impact on
        // the output.
        cmd.exec()
    }

    fn update_contractmeta_in_contract(
        &self,
        target_dir: &str,
        workspace_root: &str,
        p: &Package,
        git_data: &GitData,
    ) -> Result<(), Error> {
        let index = target_dir.find(&git_data.project_name).unwrap_or(0);
        let relative_target_dir = &target_dir[index..];

        let index = workspace_root.find(&git_data.project_name).unwrap_or(0);
        let relative_workspace_root = &workspace_root[index..];

        let manifest_path_str = p.manifest_path.as_str();
        let index = manifest_path_str.find(&git_data.project_name).unwrap_or(0);
        let relative_package_manifest_path = &manifest_path_str[index..];

        let file_path = Path::new(target_dir)
            .join("wasm32-unknown-unknown")
            .join(&self.profile);

        let target_file = format!("{}.wasm", p.name.replace('-', "_"));
        let target_file_path = file_path.join(&target_file);

        let contract_buf = fs::read(&target_file_path).map_err(Error::ReadingWasmFile)?;
        let mut meta = read_wasm_contractmeta(&contract_buf)?;

        meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
            key: StringM::from_str("target_dir").expect("StringM"),
            val: StringM::from_str(&relative_target_dir).expect("StringM"),
        }));

        meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
            key: StringM::from_str("workspace_root").expect("StringM"),
            val: StringM::from_str(&relative_workspace_root).expect("StringM"),
        }));

        meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
            key: StringM::from_str("package_manifest_path").expect("StringM"),
            val: StringM::from_str(&relative_package_manifest_path).expect("StringM"),
        }));

        meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
            key: StringM::from_str("package_name").expect("StringM"),
            val: StringM::from_str(&p.name).expect("StringM"),
        }));

        meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
            key: StringM::from_str("project_name").expect("StringM"),
            val: StringM::from_str(&git_data.project_name).expect("StringM"),
        }));

        meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
            key: StringM::from_str("git_url").expect("StringM"),
            val: StringM::from_str(&git_data.remote_url).expect("StringM"),
        }));

        meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
            key: StringM::from_str("commit_hash").expect("StringM"),
            val: StringM::from_str(&git_data.commit_hash).expect("StringM"),
        }));

        let soroban_cli_version = env!("CARGO_PKG_VERSION");
        meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
            key: StringM::from_str("soroban_cli_version").expect("StringM"),
            val: StringM::from_str(soroban_cli_version).expect("StringM"),
        }));

        let mut cursor = Limited::new(Cursor::new(vec![]), Limits::none());
        meta.iter()
            .for_each(|data| data.write_xdr(&mut cursor).unwrap());
        let meta_xdr = cursor.inner.into_inner();

        let custom_section = CustomSection {
            name: Cow::from("contractmetav0"),
            data: Cow::from(meta_xdr),
        };

        let mut wasm = read_wasm_without_contractmeta(&contract_buf)?;
        custom_section.append_to(&mut wasm);

        let backup_path = target_file_path.with_extension("back.wasm");
        fs::copy(&target_file_path, backup_path).map_err(Error::CopyingWasmFile)?;

        let temp_file = format!("{}.{}.temp", target_file, rand::random::<u32>());
        let temp_file_path = file_path.join(temp_file);

        fs::write(&temp_file_path, wasm).map_err(Error::WritingWasmFile)?;
        fs::rename(&temp_file_path, target_file_path).map_err(Error::CopyingWasmFile)?;

        Ok(())
    }
}

fn read_wasm_contractmeta(contract_buf: &[u8]) -> Result<Vec<ScMetaEntry>, Error> {
    let mut meta = vec![];
    for payload in WasmParser::new(0).parse_all(contract_buf) {
        match payload.map_err(Error::ParsingWasm)? {
            Payload::CustomSection(s) => match s.name() {
                "contractmetav0" => {
                    if !s.data().is_empty() {
                        let cursor = Cursor::new(s.data());
                        let data =
                            ScMetaEntry::read_xdr_iter(&mut Limited::new(cursor, Limits::none()))
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

fn read_wasm_without_contractmeta(contract_buf: &[u8]) -> Result<Vec<u8>, Error> {
    let buf_len = contract_buf.len();
    let mut module = Vec::with_capacity(buf_len);

    for payload in WasmParser::new(0).parse_all(contract_buf) {
        let payload = payload.map_err(Error::ParsingWasm)?;
        match payload {
            Payload::CustomSection(s) => match s.name() {
                "contractmetav0" => {
                    let range = s.range();
                    let section_header_size = calc_section_header_size(&range);

                    assert!(range.start >= section_header_size);
                    if range.start > 0 {
                        module.extend_from_slice(
                            &contract_buf[0..(range.start - section_header_size)],
                        );
                    }
                    if range.end < buf_len {
                        module.extend_from_slice(&contract_buf[range.end..buf_len]);
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

fn calc_section_header_size(range: &std::ops::Range<usize>) -> usize {
    let len = range.end - range.start;
    let mut buf = Vec::new();
    let int_enc_size = leb128::write::unsigned(&mut buf, len as u64);
    let int_enc_size = int_enc_size.expect("leb128 write");
    let section_id_byte = 1;
    int_enc_size + section_id_byte
}

#[derive(Debug, Default)]
struct GitData {
    commit_hash: String,
    remote_url: String,
    project_name: String,
}

fn git_data(workspace_root: &str) -> Result<GitData, Error> {
    let mut git_data = GitData::default();

    let mut git_cmd = Command::new("git");
    git_cmd.current_dir(workspace_root);
    git_cmd.args(["rev-parse", "HEAD"]);
    let output = git_cmd.output().map_err(Error::GitCmd)?;
    git_data.commit_hash = str::from_utf8(&output.stdout)
        .map_err(Error::Utf8)?
        .trim()
        .to_string();

    let mut git_cmd = Command::new("git");
    git_cmd.current_dir(workspace_root);
    git_cmd.args(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]);
    let output = git_cmd.output().map_err(Error::GitCmd)?;
    let mut remote_name = str::from_utf8(&output.stdout)
        .map_err(Error::Utf8)?
        .trim()
        .to_string();
    remote_name = remote_name
        .split('/')
        .next()
        .expect("Git remote name")
        .to_string();

    let mut git_cmd = Command::new("git");
    git_cmd.current_dir(workspace_root);
    git_cmd.args(["remote", "get-url", &remote_name]);
    let output = git_cmd.output().map_err(Error::GitCmd)?;
    let mut url = str::from_utf8(&output.stdout)
        .map_err(Error::Utf8)?
        .trim()
        .to_string();

    if url.starts_with("git@github.com:") {
        url = url.replace("git@github.com:", "https://github.com/");
    }
    git_data.remote_url = url;

    let mut tmp_str = git_data
        .remote_url
        .trim_start_matches("https://github.com/");
    tmp_str = tmp_str.trim_end_matches(".git");
    git_data.project_name = tmp_str
        .split("/")
        .skip(1)
        .next()
        .expect("Project name")
        .to_string();

    Ok(git_data)
}
