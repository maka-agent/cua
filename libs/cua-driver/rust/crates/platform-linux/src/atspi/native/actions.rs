// SPDX-License-Identifier: MIT
//! Original action discovery over the existing admitted AT-SPI connection.

use anyhow::{Result, anyhow, bail};
use atspi::proxy::{accessible::AccessibleProxy, action::ActionProxy};
use atspi::zbus::{fdo::PropertiesProxy, message::Message, proxy::CacheProperties};

use super::{element, reply};

const ACTION: &str = "org.a11y.atspi.Action";
const INTERFACES_INVALID: &str = "AT-SPI GetInterfaces did not return an array";
const NO_ACTION: &str = "AT-SPI element does not implement Action";
const COUNT_MISSING: &str = "AT-SPI NActions did not return a variant";
const COUNT_INVALID: &str = "AT-SPI NActions did not return an integer";
const COUNT_NEGATIVE: &str = "AT-SPI NActions returned a negative count";
const NAME_INVALID: &str = "AT-SPI action has no name";

fn interfaces(message: &Message) -> Result<()> {
    let names = reply::strings(message)?.ok_or_else(|| anyhow!(INTERFACES_INVALID))?;
    if !names.iter().any(|name| name == ACTION) {
        bail!(NO_ACTION);
    }
    Ok(())
}

fn count(message: &Message) -> Result<i32> {
    if !reply::signature(message)?.starts_with('v') {
        bail!(COUNT_MISSING);
    }
    let count = reply::variant_i32(message)?.ok_or_else(|| anyhow!(COUNT_INVALID))?;
    if count < 0 {
        bail!(COUNT_NEGATIVE);
    }
    Ok(count)
}

fn name(message: &Message) -> Result<String> {
    reply::string(message)?.ok_or_else(|| anyhow!(NAME_INVALID))
}

async fn checked<T>(
    session_id: Option<&str>,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    element::check(session_id)?;
    let result = super::call(future).await;
    element::check(session_id)?;
    result.ok_or_else(|| anyhow!("AT-SPI element lookup did not answer in time"))?
}

pub(super) async fn names(ap: &ActionProxy<'_>, session_id: Option<&str>) -> Result<Vec<String>> {
    element::check(session_id)?;
    let proxy = ap.inner();
    let accessible = AccessibleProxy::builder(proxy.connection())
        .cache_properties(CacheProperties::No)
        .destination(proxy.destination().clone())?
        .path(proxy.path().clone())?
        .build()
        .await?;
    let properties = PropertiesProxy::builder(proxy.connection())
        .cache_properties(CacheProperties::No)
        .destination(proxy.destination().clone())?
        .path(proxy.path().clone())?
        .build()
        .await?;
    // The original checks GetInterfaces before Properties.Get(NActions).
    // Raw method calls retain the successful body shape and remote error.
    let response = checked(
        session_id,
        reply::call_method(accessible.inner(), "GetInterfaces", &()),
    )
    .await?;
    interfaces(&response)?;
    let response = checked(
        session_id,
        reply::call_method(properties.inner(), "Get", &(ACTION, "NActions")),
    )
    .await?;
    let count = count(&response)?;
    let mut names = Vec::new();
    for index in 0..count {
        let response = checked(session_id, reply::call_method(proxy, "GetName", &(index,))).await?;
        names.push(name(&response)?);
    }
    // A failed name read discards the whole list, never partial indices.
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atspi::zbus::zvariant::{DynamicType, ObjectPath, Signature, Value};

    fn message<T: serde::Serialize + DynamicType>(body: &T) -> Message {
        Message::method_call("/org/cua/Fixture", "Reply")
            .unwrap()
            .build(body)
            .unwrap()
    }

    #[test]
    fn action_interfaces_require_the_first_array_and_exact_interface_name() {
        interfaces(&message(&vec!["unknown.FutureInterface", ACTION])).unwrap();
        interfaces(&message(&(vec![ACTION], 9_u32))).unwrap();
        interfaces(&message(&vec![
            Value::from(7_i32),
            Value::Value(Box::new(Value::from(ACTION))),
        ]))
        .unwrap();
        for reply in [message(&()), message(&ACTION), message(&((vec![ACTION],),))] {
            assert_eq!(
                interfaces(&reply).unwrap_err().to_string(),
                INTERFACES_INVALID
            );
        }
        for reply in [
            message(&Vec::<String>::new()),
            message(&vec!["ORG.A11Y.ATSPI.ACTION"]),
            message(&vec![7_i32]),
            message(&vec![Value::from(7_i32)]),
        ] {
            assert_eq!(interfaces(&reply).unwrap_err().to_string(), NO_ACTION);
        }
    }

    #[test]
    fn noncanonical_boolean_variant_keeps_the_native_action_count_type_error() {
        let word = super::super::reply::BooleanWord(2);
        let reply = message(&atspi::zbus::zvariant::SerializeValue(&word));
        assert_eq!(count(&reply).unwrap_err().to_string(), COUNT_INVALID);
    }

    #[test]
    fn action_count_requires_one_variant_with_a_nonnegative_i32() {
        assert_eq!(count(&message(&Value::from(0_i32))).unwrap(), 0);
        assert_eq!(
            count(&message(&(Value::from(3_i32), "ignored"))).unwrap(),
            3
        );
        for reply in [
            message(&()),
            message(&3_i32),
            message(&((Value::from(3_i32),),)),
        ] {
            assert_eq!(count(&reply).unwrap_err().to_string(), COUNT_MISSING);
        }
        for reply in [
            message(&Value::from(3_u32)),
            message(&Value::from("3")),
            message(&Value::Value(Box::new(Value::from(3_i32)))),
        ] {
            assert_eq!(count(&reply).unwrap_err().to_string(), COUNT_INVALID);
        }
        assert_eq!(
            count(&message(&Value::from(-1_i32)))
                .unwrap_err()
                .to_string(),
            COUNT_NEGATIVE
        );
    }

    #[test]
    fn action_name_keeps_empty_names_and_recursively_string_like_values() {
        assert_eq!(name(&message(&"")).unwrap(), "");
        assert_eq!(name(&message(&("Expand", false))).unwrap(), "Expand");
        assert_eq!(
            name(&message(&ObjectPath::try_from("/Expand").unwrap())).unwrap(),
            "/Expand"
        );
        assert_eq!(
            name(&message(&Signature::try_from("i").unwrap())).unwrap(),
            "i"
        );
        assert_eq!(
            name(&message(&Value::Value(Box::new(Value::from("Expand"))))).unwrap(),
            "Expand"
        );
        for reply in [message(&()), message(&7_i32), message(&(("Expand",),))] {
            assert_eq!(name(&reply).unwrap_err().to_string(), NAME_INVALID);
        }
    }
}
