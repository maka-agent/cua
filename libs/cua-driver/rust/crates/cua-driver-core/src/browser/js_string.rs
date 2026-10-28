// SPDX-License-Identifier: MIT

//! Lossless browser metadata strings retained as one JSON string literal.

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{value::RawValue, Map, Value};
use std::collections::BTreeMap;

/// One JavaScript string carried as JSON text until the JavaScript API boundary.
///
/// JSON escaping preserves isolated UTF-16 surrogates that Rust `String` cannot
/// store directly. Serialization emits ordinary text containing that literal,
/// never an unescaped raw JSON token. Equality compares the retained literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonStringLiteral(String);

impl JsonStringLiteral {
    /// Validate JSON text containing exactly one string literal.
    ///
    /// # Errors
    /// Returns a JSON error for invalid text or a non-string JSON value.
    pub fn parse(json: String) -> Result<Self, serde_json::Error> {
        let raw: &RawValue = serde_json::from_str(&json)?;
        if raw.get().as_bytes().first() != Some(&b'"') {
            return Err(serde_json::Error::custom(
                "browser metadata must be a JSON string literal",
            ));
        }
        Ok(Self(json))
    }

    /// Preserve an existing validated raw JSON string without decoding UTF-16.
    ///
    /// # Errors
    /// Returns a JSON error when the token is not a string literal.
    pub fn from_raw(raw: &RawValue) -> Result<Self, serde_json::Error> {
        if raw.get().as_bytes().first() != Some(&b'"') {
            return Err(serde_json::Error::custom(
                "browser metadata must be a JSON string literal",
            ));
        }
        Ok(Self(raw.get().to_owned()))
    }

    /// Encode an already representable Rust string without changing its value.
    pub fn from_scalar(value: &str) -> Self {
        Self(serde_json::to_string(value).expect("serializing a Rust string cannot fail"))
    }

    /// Return the encoded JSON text for an existing private transport boundary.
    pub fn json(&self) -> &str {
        &self.0
    }

    /// Decode only at an existing boundary that requires a Unicode-scalar string.
    ///
    /// # Errors
    /// Returns a JSON error for isolated UTF-16 surrogates. Callers must refuse
    /// that unsupported boundary rather than substitute or discard text.
    pub fn strict_scalar(&self) -> Result<String, serde_json::Error> {
        serde_json::from_str(self.json())
    }

    /// Decode a raw string token from a typed JSON input, before any `Value`.
    ///
    /// # Errors
    /// Returns the deserializer's error for a non-string or malformed token.
    pub fn deserialize_raw<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        Self::from_raw(&raw).map_err(D::Error::custom)
    }
}

impl Default for JsonStringLiteral {
    fn default() -> Self {
        Self("\"\"".to_owned())
    }
}
impl From<&str> for JsonStringLiteral {
    fn from(value: &str) -> Self {
        Self::from_scalar(value)
    }
}
impl From<String> for JsonStringLiteral {
    fn from(value: String) -> Self {
        Self::from_scalar(&value)
    }
}
impl Serialize for JsonStringLiteral {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.json())
    }
}
impl<'de> Deserialize<'de> for JsonStringLiteral {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Project the same source-supported fields as Chatgpt's existing `checked_tab`.
/// The caller still validates its original pending method, tab ID and scope.
/// Unknown fields do not acquire a new meaning through encoded field names.
pub(crate) fn normalize_chatgpt_tab(raw: &RawValue) -> Result<Value, serde_json::Error> {
    let fields: BTreeMap<String, Box<RawValue>> = serde_json::from_str(raw.get())?;
    let mut tab = Map::new();
    for key in [
        "id",
        "url",
        "active",
        "faviconUrl",
        "lastOpened",
        "providerTabId",
    ] {
        if let Some(value) = fields.get(key) {
            tab.insert(key.to_owned(), serde_json::from_str(value.get())?);
        }
    }
    for (source, destination) in [("title", "titleJson"), ("tabGroup", "groupTitleJson")] {
        if let Some(value) = fields.get(source) {
            let value = if value.get() == "null" {
                Value::Null
            } else {
                serde_json::to_value(JsonStringLiteral::from_raw(value)?)?
            };
            tab.insert(destination.to_owned(), value);
        }
    }
    Ok(Value::Object(tab))
}

pub(crate) fn normalize_chatgpt_tabs(raw: &RawValue) -> Result<Value, serde_json::Error> {
    let rows: Vec<Box<RawValue>> = serde_json::from_str(raw.get())?;
    rows.iter()
        .map(|row| normalize_chatgpt_tab(row))
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

/// Keep one source CDP TargetInfo's metadata strings in the same text channel.
/// The owning transport retains the full original JSON; only this typed view
/// uses these normalized field names.
pub(crate) fn normalize_cdp_target_info(raw: &RawValue) -> Result<Value, serde_json::Error> {
    let fields: BTreeMap<String, Box<RawValue>> = serde_json::from_str(raw.get())?;
    if fields.contains_key("titleJson") || fields.contains_key("groupTitleJson") {
        return Err(serde_json::Error::custom(
            "raw CDP target metadata contains encoded aliases",
        ));
    }
    if fields.contains_key("tabGroup") && fields.contains_key("groupTitle") {
        return Err(serde_json::Error::custom(
            "raw CDP target metadata contains two group titles",
        ));
    }
    let mut target = Map::new();
    for (key, value) in &fields {
        let destination = match key.as_str() {
            "title" => "titleJson",
            "tabGroup" | "groupTitle" => "groupTitleJson",
            _ => {
                target.insert(key.clone(), serde_json::from_str(value.get())?);
                continue;
            }
        };
        target.insert(
            destination.to_owned(),
            if value.get() == "null" {
                Value::Null
            } else {
                serde_json::to_value(JsonStringLiteral::from_raw(value)?)?
            },
        );
    }
    Ok(Value::Object(target))
}

pub(crate) fn normalize_cdp_targets(raw: &RawValue) -> Result<Value, serde_json::Error> {
    let fields: BTreeMap<String, Box<RawValue>> = serde_json::from_str(raw.get())?;
    if !fields.contains_key("targetInfos") {
        return Err(serde_json::Error::custom(
            "CDP target response lacks targetInfos",
        ));
    }
    let mut body = Map::new();
    for (key, value) in fields {
        let value = if key == "targetInfos" {
            let rows: Vec<Box<RawValue>> = serde_json::from_str(value.get())?;
            Value::Array(
                rows.iter()
                    .map(|row| normalize_cdp_target_info(row))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        } else {
            serde_json::from_str(value.get())?
        };
        body.insert(key, value);
    }
    Ok(Value::Object(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_surrogates_remain_escaped_text_across_ordinary_json() {
        let literal =
            JsonStringLiteral::parse(r#""\ud800 title \udc00 \\ud800 😀""#.into()).unwrap();
        let wire = serde_json::to_string(&literal).unwrap();
        let restored: JsonStringLiteral = serde_json::from_str(&wire).unwrap();
        assert_eq!(restored, literal);
        assert_eq!(restored.json(), r#""\ud800 title \udc00 \\ud800 😀""#);
        assert!(serde_json::from_str::<String>(restored.json()).is_err());
        for invalid in ["null", "7", "[]", "{}", "\"unfinished"] {
            assert!(
                JsonStringLiteral::parse(invalid.into()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn raw_tab_projection_preserves_title_and_group_without_trusting_encoded_aliases() {
        let raw: &RawValue = serde_json::from_str(r#"{"id":17,"title":"\ud800","tabGroup":"\udc00","titleJson":"\"forged\"","groupTitleJson":"\"forged group\"","url":"https://fixture.test/","active":true,"ignored":"legacy unknown"}"#).unwrap();
        let row = normalize_chatgpt_tab(raw).unwrap();
        assert_eq!(row["id"], 17);
        assert_eq!(row["titleJson"], r#""\ud800""#);
        assert_eq!(row["groupTitleJson"], r#""\udc00""#);
        assert_eq!(row["url"], "https://fixture.test/");
        assert_eq!(row["active"], true);
        assert!(row.get("title").is_none() && row.get("tabGroup").is_none());
        assert!(row.get("ignored").is_none());
    }

    #[test]
    fn absent_null_and_empty_metadata_keep_the_existing_option_contract() {
        let raw: &RawValue = serde_json::from_str(
            r#"[{"id":1},{"id":2,"title":null,"tabGroup":null},{"id":3,"title":"","tabGroup":""}]"#,
        )
        .unwrap();
        let rows = normalize_chatgpt_tabs(raw).unwrap();
        assert!(rows[0].get("titleJson").is_none());
        assert_eq!(rows[1]["titleJson"], Value::Null);
        assert_eq!(rows[1]["groupTitleJson"], Value::Null);
        assert_eq!(rows[2]["titleJson"], "\"\"");
        assert_eq!(rows[2]["groupTitleJson"], "\"\"");
    }

    #[test]
    fn typed_cdp_target_view_keeps_source_fields_and_encoded_title_together() {
        let raw: &RawValue = serde_json::from_str(r#"{"targetInfos":[{"targetId":"actual","type":"page","url":"https://fixture.test/","openerId":"opener","attached":true,"title":"\ud800","groupTitle":"\udc00","extra":{"known":1}}],"sourceFlag":false}"#).unwrap();
        let body = normalize_cdp_targets(raw).unwrap();
        let info = &body["targetInfos"][0];
        assert_eq!(info["titleJson"], r#""\ud800""#);
        assert_eq!(info["groupTitleJson"], r#""\udc00""#);
        assert_eq!(info["targetId"], "actual");
        assert_eq!(info["type"], "page");
        assert_eq!(info["url"], "https://fixture.test/");
        assert_eq!(info["openerId"], "opener");
        assert_eq!(info["attached"], true);
        assert_eq!(info["extra"]["known"], 1);
        assert_eq!(body["sourceFlag"], false);
        assert!(info.get("title").is_none());
        let forged: &RawValue = serde_json::from_str(
            r#"{"targetId":"actual","title":"real","titleJson":"\"forged\""}"#,
        )
        .unwrap();
        assert!(normalize_cdp_target_info(forged)
            .unwrap_err()
            .to_string()
            .contains("encoded aliases"));
    }
}
