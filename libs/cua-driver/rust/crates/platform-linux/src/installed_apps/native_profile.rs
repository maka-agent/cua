// SPDX-License-Identifier: MIT
//! Original Linux desktop-entry profile, beside the existing XDG app reader.
//! This supplies metadata and argv only. Actual spawning remains in the
//! existing tools launcher; no shell or input/capture implementation is added.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub id: String,
    pub name: String,
    exec: String,
    path: PathBuf,
    icon: Option<String>,
    startup_wm_class: Option<String>,
}

impl Entry {
    pub(crate) fn matches_query(&self, query: &str) -> bool {
        self.id.eq_ignore_ascii_case(query)
            || self.name.eq_ignore_ascii_case(query)
            || self
                .id
                .trim_end_matches(".desktop")
                .eq_ignore_ascii_case(query)
    }

    pub(crate) fn owns_window_class(&self, class: &str) -> bool {
        let id = self.id.trim_end_matches(".desktop");
        self.startup_wm_class
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(class))
            || self.name.eq_ignore_ascii_case(class)
            || id.eq_ignore_ascii_case(class)
            || id
                .rsplit('.')
                .next()
                .is_some_and(|value| value.eq_ignore_ascii_case(class))
    }

    pub(crate) fn argv(&self) -> Result<Vec<String>, String> {
        let tokens = tokenize(&self.exec)?;
        let mut result = Vec::new();
        for token in tokens {
            match token.as_str() {
                "%f" | "%F" | "%u" | "%U" | "%d" | "%D" | "%n" | "%N" | "%v" | "%m" => {}
                "%i" => {
                    if let Some(icon) = &self.icon {
                        result.push("--icon".to_owned());
                        result.push(icon.clone());
                    }
                }
                _ => result.push(
                    token
                        .replace("%%", "%")
                        .replace("%c", &self.name)
                        .replace("%k", &self.path.to_string_lossy()),
                ),
            }
        }
        if result.is_empty() {
            return Err("desktop entry Exec expands to an empty command".into());
        }
        Ok(result)
    }
}

/// The source profile intentionally retains the .desktop suffix in its ID.
/// A hidden/invalid user entry still masks the same system ID: seen is updated
/// before parsing, unlike the existing generic list_installed_apps projection.
pub(crate) fn entries() -> Vec<Entry> {
    scan(&roots(), &|program| {
        executable_exists(program, std::env::var_os("PATH"))
    })
}

fn roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = std::env::var_os("XDG_DATA_HOME") {
        roots.push(PathBuf::from(home).join("applications"));
    } else if let Some(home) = std::env::var_os("HOME") {
        roots.push(PathBuf::from(home).join(".local/share/applications"));
    }
    for directory in std::env::var("XDG_DATA_DIRS")
        .unwrap_or_else(|_| "/usr/local/share:/usr/share".to_owned())
        .split(':')
        .filter(|value| !value.is_empty())
    {
        roots.push(PathBuf::from(directory).join("applications"));
    }
    roots
}

fn scan(roots: &[PathBuf], executable: &dyn Fn(&str) -> bool) -> Vec<Entry> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for root in roots {
        let mut directories = vec![root.clone()];
        while let Some(directory) = directories.pop() {
            let Ok(children) = fs::read_dir(directory) else {
                continue;
            };
            for child in children.flatten() {
                let path = child.path();
                if fs::metadata(&path).is_ok_and(|metadata| metadata.is_dir()) {
                    directories.push(path);
                    continue;
                }
                if path.extension().and_then(|value| value.to_str()) != Some("desktop") {
                    continue;
                }
                let Ok(relative) = path.strip_prefix(root) else {
                    continue;
                };
                let id = relative
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("-");
                if !seen.insert(id.clone()) {
                    continue;
                }
                let Ok(text) = fs::read_to_string(&path) else {
                    continue;
                };
                if let Some(entry) = parse(&text, id, path, executable) {
                    result.push(entry);
                }
            }
        }
    }
    result
}

fn parse(
    text: &str,
    id: String,
    path: PathBuf,
    executable: &dyn Fn(&str) -> bool,
) -> Option<Entry> {
    let mut in_entry = false;
    let (mut name, mut exec, mut icon, mut startup_wm_class) = (None, None, None, None);
    let (mut kind, mut try_exec) = (None, None);
    let (mut hidden, mut terminal) = (false, false);
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Name" => name = Some(value.to_owned()),
            "Exec" => exec = Some(value.to_owned()),
            "Icon" => icon = Some(value.to_owned()),
            "StartupWMClass" => startup_wm_class = Some(value.to_owned()),
            "Type" => kind = Some(value),
            "TryExec" => try_exec = Some(value),
            "Hidden" | "NoDisplay" => hidden |= value.eq_ignore_ascii_case("true"),
            "Terminal" => terminal = value.eq_ignore_ascii_case("true"),
            _ => {}
        }
    }
    if hidden || terminal || kind != Some("Application") {
        return None;
    }
    if try_exec
        .filter(|program| !program.is_empty())
        .is_some_and(|program| !executable(program))
    {
        return None;
    }
    let entry = Entry {
        id,
        name: name?,
        exec: exec?,
        path,
        icon,
        startup_wm_class,
    };
    let argv = entry.argv().ok()?;
    if !executable(&argv[0]) {
        return None;
    }
    Some(entry)
}

/// Source executable_exists checks a regular file with any execute mode bit;
/// a single-component name searches PATH, including its empty components.
fn executable_exists(program: &str, path: Option<OsString>) -> bool {
    let file = |path: &Path| {
        fs::metadata(path)
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    };
    if Path::new(program).components().count() > 1 {
        return file(Path::new(program));
    }
    path.is_some_and(|path| {
        std::env::split_paths(&path).any(|directory| file(&directory.join(program)))
    })
}

fn tokenize(command: &str) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;
    for character in command.chars() {
        if escaped {
            word.push(character);
            escaped = false;
            started = true;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            started = true;
            continue;
        }
        if quote == Some(character) {
            quote = None;
            started = true;
            continue;
        }
        if quote.is_none() && matches!(character, '\'' | '"') {
            quote = Some(character);
            started = true;
            continue;
        }
        if quote.is_none() && character.is_whitespace() {
            if started {
                result.push(std::mem::take(&mut word));
                started = false;
            }
            continue;
        }
        word.push(character);
        started = true;
    }
    if escaped || quote.is_some() {
        return Err("desktop entry Exec has unterminated quoting or escaping".into());
    }
    if started {
        result.push(word);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_entry_argv_retains_quoted_arguments_and_exact_field_code_rules() {
        let entry=parse("[Desktop Entry]\nType=Application\nName=Fixture\nIcon=fixture-icon\nExec=\"/opt/fixture app\" '' 'literal %f' %f %i %%c %k\n",
            "fixture.desktop".into(),PathBuf::from("/fixture path/fixture.desktop"),&|_|true).unwrap();
        assert_eq!(
            entry.argv().unwrap(),
            vec![
                "/opt/fixture app",
                "",
                "literal %f",
                "--icon",
                "fixture-icon",
                "Fixture",
                "/fixture path/fixture.desktop"
            ]
        );
        assert!(entry.matches_query("FIXTURE.DESKTOP"));
        assert!(entry.matches_query("fixture"));
        assert!(!entry.matches_query("fixt"));
        assert!(tokenize("app 'unterminated").is_err());
        assert!(tokenize("app trailing\\").is_err());
    }

    #[test]
    fn hidden_user_entry_masks_system_id_and_native_ids_retain_suffix() {
        let root = tempfile::tempdir().unwrap();
        let user = root.path().join("user");
        let system = root.path().join("system");
        fs::create_dir_all(&user).unwrap();
        fs::create_dir_all(&system).unwrap();
        fs::write(
            user.join("same.desktop"),
            "[Desktop Entry]\nType=Application\nName=Hidden\nHidden=true\nExec=fixture\n",
        )
        .unwrap();
        fs::write(
            system.join("same.desktop"),
            "[Desktop Entry]\nType=Application\nName=System\nExec=fixture\n",
        )
        .unwrap();
        fs::create_dir(system.join("nested")).unwrap();
        fs::write(
            system.join("nested/visible.desktop"),
            "[Desktop Entry]\nType=Application\nName=Visible\nExec=fixture\n",
        )
        .unwrap();
        let entries = scan(&[user, system], &|_| true);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "nested-visible.desktop");
    }

    #[test]
    fn native_filters_use_exact_type_and_terminal_tryexec_and_exec_availability() {
        let path = PathBuf::from("fixture.desktop");
        for body in [
            "Name=NoType\nExec=fixture",
            "Type=application\nName=BadType\nExec=fixture",
            "Type=Application\nName=Terminal\nTerminal=TRUE\nExec=fixture",
            "Type=Application\nName=Hidden\nHidden=true\nHidden=false\nExec=fixture",
            "Type=Application\nName=TryExec\nTryExec=missing\nExec=fixture",
            "Type=Application\nName=Missing\nExec=missing",
        ] {
            assert!(
                parse(
                    &format!("[Desktop Entry]\n{body}"),
                    "fixture.desktop".into(),
                    path.clone(),
                    &|program| program == "fixture"
                )
                .is_none(),
                "{body}"
            );
        }
        let entry=parse("[Desktop Entry]\nType=Application\nName=Localized base\nName[fr]=Autre\nExec=fixture\nStartupWMClass=ExactClass",
            "org.example.Fixture.desktop".into(),path,&|_|true).unwrap();
        assert_eq!(entry.name, "Localized base");
        assert!(entry.owns_window_class("EXACTCLASS"));
        assert!(entry.owns_window_class("Fixture"));
        assert!(!entry.owns_window_class("example"));
        assert!(!entry.owns_window_class("fixture-executable"));
    }
}
