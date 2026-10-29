// SPDX-License-Identifier: MIT
//! Retain the original body signature through the existing zvariant decoder.

use anyhow::{Context, Result, bail};
use atspi::zbus::{
    Proxy,
    message::Message,
    zvariant::{DynamicType, Endian, OwnedValue, Signature, Type, serialized_size},
};
use serde::{
    Deserialize, Deserializer,
    de::{DeserializeSeed, Error, IgnoredAny, MapAccess, SeqAccess, Visitor},
};

/// The Original reader accepts every nonzero D-Bus boolean word. The existing
/// library still owns signature parsing, padding, containers and bounds checks.
struct NativeIgnored<'signature>(&'signature Signature);

impl DynamicType for NativeIgnored<'_> {
    fn signature(&self) -> Signature {
        self.0.clone()
    }
}

impl<'de> DeserializeSeed<'de> for NativeIgnored<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        match self.0 {
            // D-Bus Bool and U32 have the same library-defined representation.
            // Ask the library for the word instead of its stricter bool policy.
            Signature::Bool => u32::deserialize(deserializer).map(|_| ()),
            Signature::Variant
            | Signature::Array(_)
            | Signature::Structure(_)
            | Signature::Dict { .. } => deserializer.deserialize_any(self),
            _ => IgnoredAny::deserialize(deserializer).map(|_| ()),
        }
    }
}

impl<'de> Visitor<'de> for NativeIgnored<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a D-Bus value matching its parsed signature")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        match self.0 {
            Signature::Variant => {
                let raw: String = values
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing D-Bus variant signature"))?;
                let signature = Signature::try_from(raw.as_str()).map_err(A::Error::custom)?;
                values
                    .next_element_seed(NativeIgnored(&signature))?
                    .ok_or_else(|| A::Error::custom("missing D-Bus variant value"))?;
            }
            Signature::Array(child) => {
                while values.next_element_seed(NativeIgnored(child))?.is_some() {}
            }
            Signature::Structure(fields) => {
                for field in fields.iter() {
                    values
                        .next_element_seed(NativeIgnored(field))?
                        .ok_or_else(|| A::Error::custom("missing D-Bus structure field"))?;
                }
            }
            _ => return Err(A::Error::custom("unexpected D-Bus sequence signature")),
        }
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        let Signature::Dict { key, value } = self.0 else {
            return Err(A::Error::custom("unexpected D-Bus dictionary signature"));
        };
        while values.next_key_seed(NativeIgnored(key))?.is_some() {
            values.next_value_seed(NativeIgnored(value))?;
        }
        Ok(())
    }
}

fn ignore_variant_value<'de, A: SeqAccess<'de>>(
    values: &mut A,
    raw_signature: &str,
) -> Result<(), A::Error> {
    let signature = Signature::try_from(raw_signature).map_err(A::Error::custom)?;
    values
        .next_element_seed(NativeIgnored(&signature))?
        .ok_or_else(|| A::Error::custom("missing D-Bus variant value"))
}

struct HeaderValue(Option<String>);

impl Type for HeaderValue {
    const SIGNATURE: &'static Signature = &Signature::Variant;
}

impl<'de> Deserialize<'de> for HeaderValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HeaderVisitor;

        impl<'de> Visitor<'de> for HeaderVisitor {
            type Value = HeaderValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a variant in an already validated D-Bus header")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut fields: A) -> Result<Self::Value, A::Error> {
                let value_type: String = fields
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing D-Bus header variant signature"))?;
                if value_type == "g" {
                    let value: String = fields
                        .next_element()?
                        .ok_or_else(|| A::Error::custom("missing D-Bus header signature value"))?;
                    Ok(HeaderValue(Some(value)))
                } else {
                    ignore_variant_value(&mut fields, &value_type)?;
                    Ok(HeaderValue(None))
                }
            }
        }

        deserializer.deserialize_any(HeaderVisitor)
    }
}

type Header = (u8, u8, u8, u8, u32, u32, Vec<(u8, HeaderValue)>);

const MAX_MESSAGE_PART: usize = 0x0100_0000;
const TOO_LARGE: &str = "D-Bus message exceeds the maximum size";
const BIG_ENDIAN: &str = "big-endian D-Bus responses are unsupported";
const PROTOCOL_VERSION: &str = "unsupported D-Bus protocol version";
pub(super) const BOUNDS_MISSING: &str = "AT-SPI element did not return bounds";
pub(super) const BOUNDS_INVALID: &str = "AT-SPI element did not return valid bounds";

fn decoded_header(reply: &Message) -> Result<(Vec<(u8, HeaderValue)>, usize)> {
    let ((_, _, _, _, _, _, fields), consumed) = reply.data().deserialize::<Header>()?;
    // An empty standard header carries the primary header and array prefix.
    // The library supplies its encoded size; no byte offset/endian code lives
    // here. Subtracting it keeps unknown field bytes in the actual total.
    let empty_fields: Vec<(u8, OwnedValue)> = Vec::new();
    let prefix = serialized_size(
        reply.data().context(),
        &(reply.primary_header(), empty_fields),
    )?
    .size();
    let fields_size = consumed
        .checked_sub(prefix)
        .context("invalid D-Bus header size")?;
    Ok((fields, fields_size))
}

pub(super) fn signature(reply: &Message) -> Result<String> {
    // These are Original raw-profile checks, not generic Cua bus policy.
    let primary = reply.primary_header();
    if Endian::from(primary.endian_sig()) != Endian::Little {
        bail!(BIG_ENDIAN);
    }
    if primary.protocol_version() != 1 {
        bail!(PROTOCOL_VERSION);
    }
    if primary.body_len() as usize > MAX_MESSAGE_PART {
        bail!(TOO_LARGE);
    }
    // The public library performs endian/alignment/array/variant parsing.
    // Read only field8's signature as String so "ii" and "(ii)" stay distinct;
    // decoding to zvariant::Signature here would erase that distinction.
    let (fields, fields_size) = decoded_header(reply)?;
    if fields_size > MAX_MESSAGE_PART {
        bail!(TOO_LARGE);
    }
    let signature = fields
        .into_iter()
        .rev()
        .find_map(|(code, value)| (code == 8).then_some(value.0).flatten())
        .unwrap_or_default();
    // Parse all signature-declared values before using the first. This API
    // may leave undeclared trailing bytes; it does not impose a tail policy.
    let parsed = Signature::try_from(signature.as_str()).map_err(anyhow::Error::msg)?;
    reply
        .body()
        .data()
        .deserialize_with_seed(NativeIgnored(&parsed))?;
    Ok(signature)
}

struct I32Variant(Option<i32>);

impl<'de> Deserialize<'de> for I32Variant {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct I32Visitor;

        impl<'de> Visitor<'de> for I32Visitor {
            type Value = I32Variant;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a D-Bus variant containing a direct i32")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut fields: A) -> Result<Self::Value, A::Error> {
                let signature: String = fields
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing D-Bus variant signature"))?;
                if signature == "i" {
                    return fields
                        .next_element::<i32>()?
                        .map(|value| I32Variant(Some(value)))
                        .ok_or_else(|| A::Error::custom("missing D-Bus variant value"));
                }
                ignore_variant_value(&mut fields, &signature)?;
                Ok(I32Variant(None))
            }
        }

        deserializer.deserialize_any(I32Visitor)
    }
}

/// Read a direct i32 inside an already validated first Variant.
pub(super) fn variant_i32(reply: &Message) -> Result<Option<i32>> {
    Ok(reply
        .body()
        .data()
        .deserialize_for_signature::<_, I32Variant>(&Signature::Variant)?
        .0
        .0)
}

pub(super) fn boolean(reply: &Message) -> Result<Option<bool>> {
    if !signature(reply)?.starts_with('b') {
        return Ok(None);
    }
    let (word, _) = reply
        .body()
        .data()
        .deserialize_for_signature::<_, u32>(&Signature::Bool)?;
    Ok(Some(word != 0))
}

pub(super) fn rectangle(reply: &Message) -> Result<(i32, i32, i32, i32)> {
    let signature = signature(reply)?;
    // The original treats a missing/non-Struct first value as missing bounds.
    // Only an actual Struct with a wrong field count/type is invalid bounds.
    if !signature.starts_with('(') {
        bail!(BOUNDS_MISSING);
    }
    if !signature.starts_with("(iiii)") {
        bail!(BOUNDS_INVALID);
    }
    Ok(reply.body().deserialize_unchecked()?)
}

/// The original `Value::as_str` also descends through nested variants.
#[derive(Debug)]
struct StringVariant(Option<String>);

impl<'de> Deserialize<'de> for StringVariant {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StringVisitor;

        impl<'de> Visitor<'de> for StringVisitor {
            type Value = StringVariant;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a D-Bus variant")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut fields: A) -> Result<Self::Value, A::Error> {
                let signature: String = fields
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing D-Bus variant signature"))?;
                let value = match signature.as_str() {
                    "s" | "o" | "g" => fields.next_element::<String>()?,
                    "v" => fields
                        .next_element::<StringVariant>()?
                        .and_then(|value| value.0),
                    _ => {
                        ignore_variant_value(&mut fields, &signature)?;
                        return Ok(StringVariant(None));
                    }
                };
                Ok(StringVariant(value))
            }
        }

        // zvariant supplies the parsed variant's signature and value; this
        // visitor never reads wire offsets or implements a signature parser.
        deserializer.deserialize_any(StringVisitor)
    }
}

fn first_string(reply: &Message, signature: &str) -> Result<Option<String>> {
    let body = reply.body();
    let value = match signature.as_bytes().first() {
        Some(b's') => {
            body.data()
                .deserialize_for_signature::<_, String>(&Signature::Str)?
                .0
        }
        Some(b'o') => {
            body.data()
                .deserialize_for_signature::<_, String>(&Signature::ObjectPath)?
                .0
        }
        Some(b'g') => {
            body.data()
                .deserialize_for_signature::<_, String>(&Signature::Signature)?
                .0
        }
        Some(b'v') => {
            return Ok(body
                .data()
                .deserialize_for_signature::<_, StringVariant>(&Signature::Variant)?
                .0
                .0);
        }
        _ => return Ok(None),
    };
    Ok(Some(value))
}

pub(super) fn string(reply: &Message) -> Result<Option<String>> {
    let signature = signature(reply)?;
    first_string(reply, &signature)
}

/// Distinguish no array from an array with no string-like members.
pub(super) fn strings(reply: &Message) -> Result<Option<Vec<String>>> {
    let raw = signature(reply)?;
    if !raw.starts_with('a') {
        return Ok(None);
    }
    let parsed = Signature::try_from(raw.as_str()).map_err(anyhow::Error::msg)?;
    // A top-level list is represented by the library as a Structure. Since
    // the original signature starts with 'a', it cannot be a single struct.
    let first = match &parsed {
        Signature::Structure(fields) => fields.iter().next().context("missing array signature")?,
        other => other,
    };
    let body = reply.body();
    let values = match first {
        Signature::Array(child) => match &**child {
            Signature::Str | Signature::ObjectPath | Signature::Signature => {
                body.data()
                    .deserialize_for_signature::<_, Vec<String>>(first)?
                    .0
            }
            Signature::Variant => body
                .data()
                .deserialize_for_signature::<_, Vec<StringVariant>>(first)?
                .0
                .into_iter()
                .filter_map(|value| value.0)
                .collect(),
            _ => Vec::new(),
        },
        // Dictionary entries are not string-like. Their complete body was
        // validated above by the library, alongside all other array members.
        Signature::Dict { .. } => Vec::new(),
        _ => bail!("invalid D-Bus array signature"),
    };
    Ok(Some(values))
}

pub(super) fn native_error(
    interface: &str,
    method: &str,
    error: atspi::zbus::Error,
) -> anyhow::Error {
    match error {
        atspi::zbus::Error::MethodError(name, _, reply) => {
            let message = match string(&reply) {
                Ok(message) => message.unwrap_or_else(|| "method call failed".to_owned()),
                Err(error) => return error,
            };
            anyhow::anyhow!("D-Bus {interface}.{method} failed: {name}: {message}")
        }
        other => other.into(),
    }
}

/// One existing connection call; accepted mutations keep awaiting this future.
pub(super) async fn call_method<B: serde::Serialize + DynamicType>(
    proxy: &Proxy<'_>,
    method: &str,
    body: &B,
) -> Result<Message> {
    proxy
        .call_method(method, body)
        .await
        .map_err(|error| native_error(proxy.interface().as_str(), method, error))
}

#[cfg(test)]
#[derive(Clone, Copy, serde::Serialize)]
#[serde(transparent)]
pub(super) struct BooleanWord(pub(super) u32);

#[cfg(test)]
impl Type for BooleanWord {
    const SIGNATURE: &'static Signature = &Signature::Bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use atspi::zbus::zvariant::{DynamicType, Value};

    fn reply<T: serde::Serialize + DynamicType>(body: &T) -> Message {
        Message::method_call("/org/cua/Fixture", "Reply")
            .unwrap()
            .destination("org.cua.Fixture")
            .unwrap()
            .sender(":1.42")
            .unwrap()
            .build(body)
            .unwrap()
    }

    #[derive(serde::Serialize)]
    #[serde(transparent)]
    struct SignatureText<'text>(&'text str);

    impl Type for SignatureText<'_> {
        const SIGNATURE: &'static Signature = &Signature::Signature;
    }

    fn remote_error<T: serde::Serialize + DynamicType>(body: &T) -> atspi::zbus::Error {
        let call = Message::method_call("/org/cua/Fixture", "DoAction")
            .unwrap()
            .interface("org.a11y.atspi.Action")
            .unwrap()
            .build(&())
            .unwrap();
        let reply = Message::error(&call.header(), "org.cua.Fixture.Refused")
            .unwrap()
            .build(body)
            .unwrap();
        // Exercise the actual library error-return boundary rather than
        // inventing the MethodError payload consumed by the adapter.
        atspi::zbus::Error::from(reply)
    }

    #[test]
    fn original_boolean_words_use_nonzero_truth_and_keep_the_declared_body_shape() {
        for word in [0, 1, 2, u32::MAX] {
            let message = reply(&BooleanWord(word));
            assert_eq!(message.body().signature().to_string(), "b");
            assert_eq!(message.body().deserialize_unchecked::<u32>().unwrap(), word);
            if word > 1 {
                assert!(message.body().deserialize_unchecked::<bool>().is_err());
            }
            assert_eq!(signature(&message).unwrap(), "b");
            assert_eq!(boolean(&message).unwrap(), Some(word != 0));
        }
        assert_eq!(boolean(&reply(&2_u32)).unwrap(), None);
        assert_eq!(boolean(&reply(&((BooleanWord(2),),))).unwrap(), None);
        assert_eq!(
            boolean(&reply(&(BooleanWord(2), "ignored"))).unwrap(),
            Some(true)
        );
    }

    #[test]
    fn native_body_validation_reads_noncanonical_booleans_inside_library_containers() {
        use atspi::zbus::zvariant::SerializeValue;
        use std::collections::BTreeMap;

        let word = BooleanWord(2);
        let variant = SerializeValue(&word);
        let nested = SerializeValue(&variant);
        let dictionary = BTreeMap::from([("word", word)]);
        for (message, expected) in [
            (reply(&vec![word]), "ab"),
            (reply(&((word, "nested"),)), "(bs)"),
            (reply(&variant), "v"),
            (reply(&nested), "v"),
            (reply(&vec![SerializeValue(&word)]), "av"),
            (reply(&dictionary), "a{sb}"),
        ] {
            assert_eq!(signature(&message).unwrap(), expected);
        }
        assert_eq!(
            string(&reply(&("kept", word))).unwrap().as_deref(),
            Some("kept")
        );
        assert_eq!(string(&reply(&nested)).unwrap(), None);
        assert_eq!(
            strings(&reply(&vec![SerializeValue(&word)])).unwrap(),
            Some(Vec::new())
        );
        assert_eq!(strings(&reply(&dictionary)).unwrap(), Some(Vec::new()));
    }

    #[test]
    fn native_boolean_compatibility_still_requires_the_complete_library_word() {
        #[derive(serde::Serialize)]
        #[serde(transparent)]
        struct ShortBoolean(u8);

        impl Type for ShortBoolean {
            const SIGNATURE: &'static Signature = &Signature::Bool;
        }

        let message = reply(&ShortBoolean(2));
        assert_eq!(message.primary_header().body_len(), 1);
        assert!(signature(&message).is_err());
        assert!(boolean(&message).is_err());
    }

    #[test]
    fn original_remote_error_retains_interface_method_name_and_first_string_like_value() {
        let nested = Value::Value(Box::new(Value::Value(Box::new(Value::from("nested")))));
        let cases = [
            (remote_error(&"denied"), "denied"),
            (remote_error(&("first", 7_i32)), "first"),
            (remote_error(&("first", BooleanWord(2))), "first"),
            (remote_error(&BooleanWord(2)), "method call failed"),
            (remote_error(&""), ""),
            (remote_error(&nested), "nested"),
            (
                remote_error(&atspi::zbus::zvariant::ObjectPath::try_from("/denied").unwrap()),
                "/denied",
            ),
            (remote_error(&SignatureText("ii")), "ii"),
            (remote_error(&()), "method call failed"),
            (remote_error(&(7_i32, "ignored")), "method call failed"),
            (remote_error(&(("a struct",),)), "method call failed"),
            (remote_error(&Value::from(7_i32)), "method call failed"),
        ];
        for (error, expected) in cases {
            assert_eq!(
                native_error("org.a11y.atspi.Action", "DoAction", error).to_string(),
                format!(
                    "D-Bus org.a11y.atspi.Action.DoAction failed: org.cua.Fixture.Refused: {expected}"
                )
            );
        }
        let local = atspi::zbus::Error::Failure("local transport failure".to_owned());
        let expected = local.to_string();
        assert_eq!(
            native_error("org.a11y.atspi.Action", "DoAction", local).to_string(),
            expected
        );
    }

    #[test]
    fn string_like_arrays_keep_variants_and_raw_signature_text() {
        assert_eq!(
            string(&reply(&SignatureText("ii"))).unwrap().as_deref(),
            Some("ii")
        );
        assert_eq!(
            strings(&reply(&(vec![SignatureText("ii")], false))).unwrap(),
            Some(vec!["ii".into()])
        );
        assert_eq!(
            strings(&reply(&vec![
                Value::from("first"),
                Value::from(7_i32),
                Value::Value(Box::new(Value::from("last"))),
            ]))
            .unwrap(),
            Some(vec!["first".into(), "last".into()])
        );
        assert_eq!(strings(&reply(&vec![7_i32])).unwrap(), Some(Vec::new()));
        assert_eq!(strings(&reply(&((vec!["first"],),))).unwrap(), None);
    }

    #[test]
    fn original_signature_preserves_top_level_values_and_single_struct() {
        assert_eq!(signature(&reply(&())).unwrap(), "");
        assert_eq!(signature(&reply(&7_i32)).unwrap(), "i");
        assert_eq!(signature(&reply(&(7_i32, 8_i32))).unwrap(), "ii");
        assert_eq!(signature(&reply(&((7_i32, 8_i32),))).unwrap(), "(ii)");
        assert_eq!(
            signature(&reply(&(Value::from(-7_i32), 8_u32))).unwrap(),
            "vu"
        );
        assert_eq!(
            signature(&reply(&((1_i32, 2_i32, 3_i32, 4_i32), true))).unwrap(),
            "(iiii)b"
        );
        for endian in [
            atspi::zbus::zvariant::Endian::Little,
            atspi::zbus::zvariant::Endian::Big,
        ] {
            let message = Message::method_call("/org/cua/Fixture", "Reply")
                .unwrap()
                .endian(endian)
                .build(&(7_i32, true))
                .unwrap();
            assert_eq!(message.body().deserialize_unchecked::<i32>().unwrap(), 7);
            if endian == Endian::Little {
                assert_eq!(signature(&message).unwrap(), "ib");
            } else {
                assert_eq!(
                    signature(&message).unwrap_err().to_string(),
                    BIG_ENDIAN,
                    "the library's Big support cannot widen the Original native profile"
                );
            }
        }
    }

    #[test]
    fn original_rectangle_distinguishes_missing_struct_from_invalid_struct() {
        assert_eq!(
            rectangle(&reply(&((-5_i32, -3_i32, 3_i32, 5_i32),))).unwrap(),
            (-5, -3, 3, 5)
        );
        assert_eq!(
            rectangle(&reply(&((1_i32, 2_i32, 3_i32, 4_i32), true))).unwrap(),
            (1, 2, 3, 4)
        );
        // Geometric emptiness is the caller's later check, not this reader.
        assert_eq!(
            rectangle(&reply(&((1_i32, 2_i32, -3_i32, 0_i32),))).unwrap(),
            (1, 2, -3, 0)
        );
        for message in [
            reply(&()),
            reply(&true),
            reply(&(1_i32, 2_i32, 3_i32, 4_i32)),
            reply(&Value::from((1_i32, 2_i32, 3_i32, 4_i32))),
        ] {
            assert_eq!(rectangle(&message).unwrap_err().to_string(), BOUNDS_MISSING);
        }
        for message in [
            reply(&((1_i32, 2_i32, 3_i32),)),
            reply(&((1_i32, 2_i32, 3_u32, 4_i32),)),
            reply(&(((1_i32, 2_i32, 3_i32, 4_i32),),)),
            reply(&((1_i32, 2_i32, 3_i32, 4_i32, 5_i32),)),
        ] {
            assert_eq!(rectangle(&message).unwrap_err().to_string(), BOUNDS_INVALID);
        }
    }

    fn method_return<T: serde::Serialize + DynamicType>(path: &str, body: &T) -> Message {
        let call = Message::method_call("/org/cua/Fixture", "Call")
            .unwrap()
            .build(&())
            .unwrap();
        Message::method_return(&call.header())
            .unwrap()
            .path(path)
            .unwrap()
            .build(body)
            .unwrap()
    }

    // Only known fields are used in these fixtures, so the public Header
    // accessor can be independently serialized without dropping unknown data.
    fn fixture_fields_size(reply: &Message) -> usize {
        let empty: Vec<(u8, OwnedValue)> = Vec::new();
        serialized_size(reply.data().context(), &reply.header())
            .unwrap()
            .size()
            - serialized_size(reply.data().context(), &(reply.primary_header(), empty))
                .unwrap()
                .size()
    }

    #[test]
    fn original_body_limit_accepts_exact_sixteen_mib_and_refuses_one_extra_byte() {
        let empty: Vec<u8> = Vec::new();
        let small = method_return("/org/cua/Fixture", &empty);
        let overhead = serialized_size(small.body().data().context(), &empty)
            .unwrap()
            .size();
        let at_limit = method_return("/org/cua/Fixture", &vec![0_u8; MAX_MESSAGE_PART - overhead]);
        assert_eq!(
            at_limit.primary_header().body_len() as usize,
            MAX_MESSAGE_PART
        );
        assert_eq!(signature(&at_limit).unwrap(), "ay");
        drop(at_limit);
        let too_large = method_return(
            "/org/cua/Fixture",
            &vec![0_u8; MAX_MESSAGE_PART - overhead + 1],
        );
        assert_eq!(
            too_large.primary_header().body_len() as usize,
            MAX_MESSAGE_PART + 1
        );
        assert_eq!(signature(&too_large).unwrap_err().to_string(), TOO_LARGE);
    }

    #[test]
    fn original_header_limit_counts_real_array_bytes_with_inclusive_boundary() {
        let small_path = format!("/{}", "a".repeat(64));
        let small = method_return(&small_path, &(1_u8, 2_u8));
        let small_size = fixture_fields_size(&small);
        assert_eq!(small_size % 8, 0);
        let path = format!("{small_path}{}", "a".repeat(MAX_MESSAGE_PART - small_size));
        let at_limit = method_return(&path, &(1_u8, 2_u8));
        assert_eq!(fixture_fields_size(&at_limit), MAX_MESSAGE_PART);
        assert_eq!(decoded_header(&at_limit).unwrap().1, MAX_MESSAGE_PART);
        assert_eq!(signature(&at_limit).unwrap(), "yy");
        drop(at_limit);
        // Change only the final standard signature field's string length.
        let beyond = method_return(&path, &(1_u8, 2_u8, 3_u8));
        assert_eq!(fixture_fields_size(&beyond), MAX_MESSAGE_PART + 1);
        assert_eq!(decoded_header(&beyond).unwrap().1, MAX_MESSAGE_PART + 1);
        assert_eq!(signature(&beyond).unwrap_err().to_string(), TOO_LARGE);
        drop(beyond);
        let below = method_return(&path, &1_u8);
        assert_eq!(fixture_fields_size(&below), MAX_MESSAGE_PART - 1);
        assert_eq!(signature(&below).unwrap(), "y");
    }
}
