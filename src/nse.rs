use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
    rc::Rc,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use mlua::{Function, HookTriggers, Lua, LuaOptions, LuaSerdeExt, StdLib, Table, Value, VmState};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const MAX_SCRIPT_BYTES: u64 = 1024 * 1024;
const MAX_LIBRARY_MODULE_BYTES: u64 = 1024 * 1024;
const MAX_SCRIPT_MEMORY_BYTES: usize = 16 * 1024 * 1024;
const MAX_SCRIPT_INSTRUCTIONS: u32 = 100;
const SCRIPT_INSTRUCTION_INTERVAL: u32 = 10_000;
const MAX_OUTPUT_CHARS: usize = 2_048;
const MAX_HTTP_RESPONSE_BYTES: usize = 32 * 1024;
pub const DEFAULT_NSE_SCRIPT_DIRECTORY: &str = "/usr/share/netmapper/nse/scripts";
pub const MAX_NSE_EXECUTIONS: usize = 4_096;

pub fn list_nse_scripts(script_directory: &Path) -> Result<Vec<String>> {
    let mut scripts = fs::read_dir(script_directory)
        .with_context(|| {
            format!(
                "could not read NSE script directory {}; install nmap-common or set --nse-script-dir",
                script_directory.display()
            )
        })?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            (path.extension().is_some_and(|extension| extension == "nse"))
                .then(|| path.file_stem()?.to_str().map(str::to_string))
                .flatten()
        })
        .collect::<Vec<_>>();
    scripts.sort_unstable();
    if scripts.len() > 2_048 {
        bail!("NSE directory contains more than 2,048 scripts; refusing an unbounded run");
    }
    if scripts.is_empty() {
        bail!("no .nse scripts found in {}", script_directory.display());
    }
    Ok(scripts)
}

pub async fn run_nse_scripts_for_endpoint(
    script_directory: &Path,
    scripts: &[String],
    target: IpAddr,
    port_number: u16,
    service: &str,
    timeout_duration: Duration,
) -> Vec<String> {
    if service != "http" && !super::is_plaintext_http_port(port_number) {
        return vec![
            "NSE engine: skipped; this endpoint is not a supported plaintext HTTP service."
                .to_string(),
        ];
    }
    let Some(response) = fetch_http_response(target, port_number, timeout_duration).await else {
        return vec![
            "NSE engine: no plaintext HTTP response; selected scripts were not run.".to_string(),
        ];
    };
    let mut findings = Vec::new();
    let mut matched = 0usize;
    let mut unsupported = 0usize;
    for script in scripts {
        match run_nse_file(
            script_directory,
            script,
            &target.to_string(),
            port_number,
            service,
            &response,
        ) {
            Ok(Some(output)) => {
                matched += 1;
                findings.push(output);
            }
            Ok(None) => {}
            Err(_) => unsupported += 1,
        }
    }
    let total = scripts.len();
    let mut summary = vec![format!(
        "NSE engine: {matched} script(s) returned output; {unsupported} script(s) unsupported or blocked; evaluated {total} selected script(s)."
    )];
    summary.extend(findings.into_iter().take(32));
    summary
}

async fn fetch_http_response(
    target: IpAddr,
    port_number: u16,
    timeout_duration: Duration,
) -> Option<ScriptHttpResponse> {
    timeout(timeout_duration, async {
        let address = SocketAddr::new(target, port_number);
        let mut stream = TcpStream::connect(address).await.ok()?;
        let host = target.to_string();
        stream
            .write_all(
                format!(
                    "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: netmapper/{}\r\nConnection: close\r\n\r\n",
                    env!("CARGO_PKG_VERSION")
                )
                .as_bytes(),
            )
            .await
            .ok()?;
        let mut bytes = Vec::new();
        let mut chunk = [0; 4096];
        while bytes.len() < MAX_HTTP_RESPONSE_BYTES {
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..read.min(MAX_HTTP_RESPONSE_BYTES - bytes.len())]);
        }
        let response = String::from_utf8_lossy(&bytes);
        let (header_text, body) = response.split_once("\r\n\r\n")?;
        let mut header_lines = header_text.lines();
        let status = header_lines
            .next()?
            .split_whitespace()
            .nth(1)?
            .parse::<u16>()
            .ok()?;
        let headers = header_lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
            .collect();
        Some(ScriptHttpResponse {
            status,
            headers,
            body: body.to_string(),
        })
    })
    .await
    .ok()
    .flatten()
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ScriptHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

pub fn run_nse_file(
    script_directory: &Path,
    script_name: &str,
    target: &str,
    port_number: u16,
    service: &str,
    response: &ScriptHttpResponse,
) -> Result<Option<String>> {
    let name = script_name.strip_suffix(".nse").unwrap_or(script_name);
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("NSE script name must be a simple script name, without a path");
    }
    let root = script_directory.canonicalize().with_context(|| {
        format!(
            "could not access NSE script directory {}",
            script_directory.display()
        )
    })?;
    let path = root.join(format!("{name}.nse"));
    let canonical_path = path
        .canonicalize()
        .with_context(|| format!("NSE script not found: {name}"))?;
    if !canonical_path.starts_with(&root) {
        bail!("NSE script path escapes the configured script directory");
    }
    let metadata = fs::metadata(&canonical_path)
        .with_context(|| format!("could not inspect NSE script {name}"))?;
    if metadata.len() > MAX_SCRIPT_BYTES {
        bail!("NSE script {name} exceeds the 1 MiB size limit");
    }
    let source = fs::read_to_string(&canonical_path)
        .with_context(|| format!("could not read NSE script {name}"))?;
    let library_directory = root.parent().map(|parent| parent.join("nselib"));
    run_nse_source(
        name,
        &source,
        target,
        port_number,
        service,
        response,
        library_directory.as_deref(),
    )
}

fn run_nse_source(
    script_name: &str,
    source: &str,
    target: &str,
    port_number: u16,
    service: &str,
    response: &ScriptHttpResponse,
    library_directory: Option<&Path>,
) -> Result<Option<String>> {
    let lua = Lua::new_with(
        StdLib::STRING | StdLib::TABLE | StdLib::MATH | StdLib::UTF8,
        LuaOptions::default(),
    )
    .context("could not create the sandboxed Lua runtime")?;
    lua.set_memory_limit(MAX_SCRIPT_MEMORY_BYTES)
        .context("could not set the NSE memory limit")?;
    let instruction_count = Rc::new(Cell::new(0u32));
    let counted_instructions = Rc::clone(&instruction_count);
    lua.set_hook(
        HookTriggers::new().every_nth_instruction(SCRIPT_INSTRUCTION_INTERVAL),
        move |_lua, _debug| {
            let count = counted_instructions.get().saturating_add(1);
            counted_instructions.set(count);
            if count > MAX_SCRIPT_INSTRUCTIONS {
                return Err(mlua::Error::RuntimeError(
                    "NSE instruction limit exceeded".to_string(),
                ));
            }
            Ok(VmState::Continue)
        },
    )
    .context("could not configure the NSE instruction limit")?;

    let response = response.clone();
    let http_module = lua.create_table()?;
    for method in ["head", "get"] {
        let response = response.clone();
        http_module.set(
            method,
            lua.create_function(
                move |lua, (_host, _port, _path, _options): (Table, Table, Value, Value)| {
                    http_response_table(lua, &response)
                },
            )?,
        )?;
    }

    let shortport_module = lua.create_table()?;
    shortport_module.set(
        "http",
        lua.create_function(|_, (_host, port): (Table, Table)| {
            let number: u16 = port.get("number").unwrap_or_default();
            let service: String = port.get("service").unwrap_or_default();
            Ok(service == "http"
                || matches!(number, 443 | 8443)
                || super::is_plaintext_http_port(number))
        })?,
    )?;
    shortport_module.set(
        "ssl",
        lua.create_function(|_, (_host, port): (Table, Table)| {
            let tunnel: String = port.get("tunnel").unwrap_or_default();
            Ok(tunnel == "ssl")
        })?,
    )?;
    shortport_module.set(
        "port_or_service",
        lua.create_function(
            |lua, (port_values, service_values, protocol): (Value, Value, Option<String>)| {
                let ports = values_as_u16_set(port_values)?;
                let services = values_as_string_set(service_values)?;
                lua.create_function(move |_, (_host, port): (Table, Table)| {
                    let number: u16 = port.get("number").unwrap_or_default();
                    let service: String = port.get("service").unwrap_or_default();
                    let actual_protocol: String = port.get("protocol").unwrap_or_default();
                    Ok((ports.contains(&number) || services.contains(&service))
                        && protocol
                            .as_ref()
                            .is_none_or(|expected| actual_protocol.eq_ignore_ascii_case(expected)))
                })
            },
        )?,
    )?;

    let stdnse_module = lua.create_table()?;
    stdnse_module.set(
        "output_table",
        lua.create_function(|lua, ()| lua.create_table())?,
    )?;
    stdnse_module.set(
        "get_script_args",
        lua.create_function(|_, _name: String| Ok::<Option<String>, mlua::Error>(None))?,
    )?;
    stdnse_module.set(
        "format_output",
        lua.create_function(|lua, (success, value): (bool, Value)| {
            if success {
                value_to_text(lua, value)
            } else {
                Ok(format!(
                    "script check failed: {}",
                    value_to_text(lua, value)?
                ))
            }
        })?,
    )?;

    let globals = lua.globals();
    let string_module: Table = globals.get("string")?;
    let table_module: Table = globals.get("table")?;
    let math_module: Table = globals.get("math")?;
    let utf8_module: Table = globals.get("utf8")?;
    let module_cache = lua.create_table()?;
    let library_directory = library_directory.map(Path::to_path_buf);
    let require = lua.create_function(move |lua, name: String| match name.as_str() {
        "http" => Ok(Value::Table(http_module.clone())),
        "shortport" => Ok(Value::Table(shortport_module.clone())),
        "stdnse" => Ok(Value::Table(stdnse_module.clone())),
        "string" => Ok(Value::Table(string_module.clone())),
        "table" => Ok(Value::Table(table_module.clone())),
        "math" => Ok(Value::Table(math_module.clone())),
        "utf8" => Ok(Value::Table(utf8_module.clone())),
        _ => {
            let cached: Value = module_cache.get(name.as_str())?;
            if !matches!(cached, Value::Nil) {
                return Ok(cached);
            }
            let module = load_nselib_module(lua, library_directory.as_deref(), &name)?;
            module_cache.set(name, module.clone())?;
            Ok(module)
        }
    })?;
    globals.set("require", require)?;
    globals.set("SCRIPT_NAME", script_name)?;

    lua.load(source)
        .set_name(script_name)
        .exec()
        .with_context(|| format!("could not load NSE script {script_name}"))?;

    let categories: Table = globals
        .get("categories")
        .with_context(|| format!("NSE script {script_name} has no categories table"))?;
    let mut category_names = BTreeSet::new();
    for category in categories.sequence_values::<String>() {
        category_names.insert(category?);
    }
    if category_names
        .iter()
        .any(|category| matches!(category.as_str(), "brute" | "dos" | "fuzzer" | "intrusive"))
    {
        bail!(
            "NSE script {script_name} has an intrusive category and is blocked by the safe engine"
        );
    }

    let host = lua.create_table()?;
    host.set("ip", target)?;
    host.set("name", target)?;
    let port = lua.create_table()?;
    port.set("number", port_number)?;
    port.set("protocol", "tcp")?;
    port.set("service", service)?;
    port.set("state", "open")?;
    port.set(
        "tunnel",
        if matches!(port_number, 443 | 8443) {
            "ssl"
        } else {
            "none"
        },
    )?;

    let port_rule: Function = globals
        .get("portrule")
        .with_context(|| format!("NSE script {script_name} has no portrule"))?;
    if !port_rule
        .call::<bool>((host.clone(), port.clone()))
        .with_context(|| format!("NSE portrule failed in {script_name}"))?
    {
        return Ok(None);
    }
    let action: Function = globals
        .get("action")
        .with_context(|| format!("NSE script {script_name} has no action"))?;
    let output: Value = action
        .call((host, port))
        .with_context(|| format!("NSE action failed in {script_name}"))?;
    if matches!(output, Value::Nil | Value::Boolean(false)) {
        return Ok(None);
    }
    let rendered = value_to_text(&lua, output)?;
    let rendered: String = rendered
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_OUTPUT_CHARS)
        .collect();
    Ok((!rendered.is_empty()).then(|| format!("{script_name}: {rendered}")))
}

fn load_nselib_module(
    lua: &Lua,
    library_directory: Option<&Path>,
    name: &str,
) -> mlua::Result<Value> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(mlua::Error::RuntimeError(format!(
            "unsupported NSE module: {name}"
        )));
    }
    let directory = library_directory
        .and_then(|directory| directory.canonicalize().ok())
        .ok_or_else(|| mlua::Error::RuntimeError(format!("unsupported NSE module: {name}")))?;
    let path = directory
        .join(format!("{name}.lua"))
        .canonicalize()
        .map_err(mlua::Error::external)?;
    if !path.starts_with(&directory) {
        return Err(mlua::Error::RuntimeError(format!(
            "NSE module path escapes nselib: {name}"
        )));
    }
    let metadata = fs::metadata(&path).map_err(mlua::Error::external)?;
    if metadata.len() > MAX_LIBRARY_MODULE_BYTES {
        return Err(mlua::Error::RuntimeError(format!(
            "NSE module {name} exceeds the 1 MiB size limit"
        )));
    }
    let source = fs::read_to_string(path).map_err(mlua::Error::external)?;
    let module = lua.load(&source).set_name(name).eval::<Value>()?;
    Ok(if matches!(module, Value::Nil) {
        Value::Boolean(true)
    } else {
        module
    })
}

fn http_response_table(lua: &Lua, response: &ScriptHttpResponse) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    table.set("status", response.status)?;
    table.set("header", lua.to_value(&response.headers)?)?;
    table.set("body", response.body.as_str())?;
    Ok(table)
}

fn values_as_u16_set(value: Value) -> mlua::Result<BTreeSet<u16>> {
    match value {
        Value::Table(values) => values.sequence_values().collect(),
        Value::Integer(value) if (0..=u16::MAX as i64).contains(&value) => {
            Ok([value as u16].into_iter().collect())
        }
        Value::Nil => Ok(BTreeSet::new()),
        _ => Err(mlua::Error::RuntimeError(
            "unsupported NSE port rule".to_string(),
        )),
    }
}

fn values_as_string_set(value: Value) -> mlua::Result<BTreeSet<String>> {
    match value {
        Value::String(value) => Ok([value.to_str()?.to_string()].into_iter().collect()),
        Value::Table(values) => values.sequence_values().collect(),
        Value::Nil => Ok(BTreeSet::new()),
        _ => Err(mlua::Error::RuntimeError(
            "unsupported NSE service rule".to_string(),
        )),
    }
}

fn value_to_text(lua: &Lua, value: Value) -> mlua::Result<String> {
    match value {
        Value::Nil => Ok(String::new()),
        Value::String(value) => Ok(value.to_str()?.to_string()),
        value @ Value::Table(_) => {
            let json: serde_json::Value = lua.from_value(value)?;
            serde_json::to_string(&json).map_err(mlua::Error::external)
        }
        value => Ok(value.to_string()?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{io::AsyncWriteExt, net::TcpListener};

    fn response() -> ScriptHttpResponse {
        ScriptHttpResponse {
            status: 200,
            headers: [
                ("server".to_string(), "fixture/1.0".to_string()),
                ("x-content-type-options".to_string(), "nosniff".to_string()),
            ]
            .into_iter()
            .collect(),
            body: String::new(),
        }
    }

    #[test]
    fn executes_a_sandboxed_http_nse_subset() {
        let source = r#"
            local http = require "http"
            local shortport = require "shortport"
            local stdnse = require "stdnse"
            categories = {"safe", "discovery"}
            portrule = shortport.port_or_service({80}, "http", "tcp")
            action = function(host, port)
                local response = http.head(host, port, "/")
                local output = stdnse.output_table()
                output.server = response.header.server
                return output
            end
        "#;
        let output = run_nse_source(
            "fixture",
            source,
            "192.0.2.10",
            80,
            "http",
            &response(),
            None,
        )
        .unwrap()
        .unwrap();
        assert!(output.contains("fixture/1.0"));
    }

    #[test]
    fn loads_lua_modules_from_the_configured_nselib_directory() {
        let directory = std::env::temp_dir().join(format!(
            "netmapper-nselib-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("fixture.lua"),
            r#"return {label = "loaded from nselib"}"#,
        )
        .unwrap();
        let source = r#"
            local fixture = require "fixture"
            categories = {"safe"}
            portrule = function() return true end
            action = function() return fixture.label end
        "#;
        let output = run_nse_source(
            "module-fixture",
            source,
            "192.0.2.10",
            80,
            "http",
            &response(),
            Some(&directory),
        )
        .unwrap()
        .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        assert!(output.contains("loaded from nselib"));
    }

    #[test]
    fn blocks_intrusive_categories_and_unsupported_modules() {
        let intrusive = r#"
            categories = {"vuln", "dos"}
            portrule = function() return true end
            action = function() return "should not run" end
        "#;
        let intrusive_error = run_nse_source(
            "intrusive",
            intrusive,
            "127.0.0.1",
            80,
            "http",
            &response(),
            None,
        )
        .unwrap_err();
        assert!(format!("{intrusive_error:#}").contains("intrusive category"));

        let unsupported = r#"
            local nmap = require "nmap"
            categories = {"safe"}
            portrule = function() return true end
            action = function() return "not reached" end
        "#;
        let unsupported_error = run_nse_source(
            "unsupported",
            unsupported,
            "127.0.0.1",
            80,
            "http",
            &response(),
            None,
        )
        .unwrap_err();
        assert!(format!("{unsupported_error:#}").contains("unsupported NSE module"));
    }

    #[test]
    fn stops_scripts_that_exceed_the_instruction_budget() {
        let infinite = r#"
            categories = {"safe"}
            portrule = function() return true end
            action = function() while true do end end
        "#;
        let error = run_nse_source("loop", infinite, "127.0.0.1", 80, "http", &response(), None)
            .unwrap_err();
        assert!(format!("{error:#}").contains("instruction limit"));
    }

    #[test]
    fn runs_the_installed_nmap_http_security_headers_script() {
        let script_directory = Path::new("/usr/share/nmap/scripts");
        if !script_directory.join("http-security-headers.nse").is_file() {
            return;
        }
        let response = ScriptHttpResponse {
            status: 200,
            headers: [(
                "content-security-policy".to_string(),
                "default-src 'self'".to_string(),
            )]
            .into_iter()
            .collect(),
            body: String::new(),
        };
        let output = run_nse_file(
            script_directory,
            "http-security-headers",
            "192.0.2.10",
            80,
            "http",
            &response,
        )
        .unwrap()
        .unwrap();
        assert!(output.contains("Content_Security_Policy"));
    }

    #[tokio::test]
    async fn executes_installed_nse_script_against_loopback_http_response() {
        let script_directory = Path::new("/usr/share/nmap/scripts");
        if !script_directory.join("http-security-headers.nse").is_file() {
            return;
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.0 200 OK\r\nServer: loopback-test/1\r\nX-Content-Type-Options: nosniff\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let output = run_nse_scripts_for_endpoint(
            script_directory,
            &["http-security-headers".to_string()],
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            "http",
            Duration::from_secs(1),
        )
        .await;
        server.await.unwrap();
        assert!(output
            .iter()
            .any(|finding| finding.contains("http-security-headers")));
    }

    #[tokio::test]
    async fn skips_non_http_services_without_sending_http_data() {
        let findings = run_nse_scripts_for_endpoint(
            Path::new("/usr/share/nmap/scripts"),
            &["http-security-headers".to_string()],
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            9,
            "ssh",
            Duration::from_millis(100),
        )
        .await;
        assert!(findings[0].contains("not a supported plaintext HTTP service"));
    }
}
