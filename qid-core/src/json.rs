//! JSON utility types: JCS (RFC 8785), JSON Pointer (RFC 6901),
//! JSON Patch (RFC 6902), JSON Merge Patch (RFC 7386).

use crate::error::{QidError, QidResult};
use serde_json::Value;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// JSON Canonicalisation Scheme (JCS, RFC 8785)
// ---------------------------------------------------------------------------

/// Serialise `value` to a JCS (RFC 8785) canonical JSON string.
pub fn jcs_stringify(value: &Value) -> String {
    let mut out = String::new();
    jcs_serialize(value, &mut out);
    out
}

fn jcs_serialize(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // RFC 8785 §3.2.3: no leading zeros, no trailing dot, no exponent.
            out.push_str(&n.to_string());
        }
        Value::String(s) => {
            out.push('"');
            for ch in s.chars() {
                match ch {
                    '\"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\x08' => out.push_str("\\b"),
                    '\x0c' => out.push_str("\\f"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        out.push_str(&format!("\\u{:04x}", c as u32));
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_serialize(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let sorted: BTreeMap<&str, &Value> = map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            for (i, (key, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_serialize(&Value::String(key.to_string()), out);
                out.push(':');
                jcs_serialize(val, out);
            }
            out.push('}');
        }
    }
}

// ---------------------------------------------------------------------------
// JSON Pointer (RFC 6901)
// ---------------------------------------------------------------------------

/// Evaluate a JSON Pointer (RFC 6901) against `root` and return a
/// reference to the matched value, or an error.
pub fn json_pointer_get<'a>(root: &'a Value, pointer: &str) -> QidResult<&'a Value> {
    if !pointer.starts_with('/') && !pointer.is_empty() {
        return Err(QidError::BadRequest {
            message: format!("JSON Pointer must start with '/': {pointer}"),
        });
    }
    if pointer.is_empty() {
        return Ok(root);
    }
    let mut current = root;
    for token in pointer[1..].split('/') {
        let decoded = json_pointer_unescape(token);
        match current {
            Value::Object(map) => {
                current = map.get(&decoded).ok_or_else(|| QidError::BadRequest {
                    message: format!("JSON Pointer {pointer}: key '{decoded}' not found"),
                })?;
            }
            Value::Array(arr) => {
                let idx: usize = decoded.parse().map_err(|_| QidError::BadRequest {
                    message: format!("JSON Pointer {pointer}: invalid array index '{decoded}'"),
                })?;
                current = arr.get(idx).ok_or_else(|| QidError::BadRequest {
                    message: format!("JSON Pointer {pointer}: index {idx} out of bounds"),
                })?;
            }
            _ => {
                return Err(QidError::BadRequest {
                    message: format!("JSON Pointer {pointer}: cannot index into scalar"),
                });
            }
        }
    }
    Ok(current)
}

fn json_pointer_unescape(token: &str) -> String {
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(ch) = chars.next() {
        if ch == '~' {
            match chars.next() {
                Some('0') => out.push('~'),
                Some('1') => out.push('/'),
                _ => out.push('~'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// JSON Patch (RFC 6902)
// ---------------------------------------------------------------------------

/// Apply a JSON Patch (RFC 6902) to a JSON value.
pub fn json_patch_apply(root: &mut Value, patch: &Value) -> QidResult<()> {
    let ops = patch.as_array().ok_or_else(|| QidError::BadRequest {
        message: "JSON Patch must be an array of operations".to_string(),
    })?;
    for op in ops {
        let op_type =
            op.get("op")
                .and_then(|v| v.as_str())
                .ok_or_else(|| QidError::BadRequest {
                    message: "JSON Patch operation missing 'op'".to_string(),
                })?;
        let path = op
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| QidError::BadRequest {
                message: "JSON Patch operation missing 'path'".to_string(),
            })?;
        match op_type {
            "remove" => {
                json_pointer_remove(root, path)?;
            }
            "replace" => {
                let value = op.get("value").ok_or_else(|| QidError::BadRequest {
                    message: "JSON Patch replace missing 'value'".to_string(),
                })?;
                json_pointer_set(root, path, value.clone())?;
            }
            "add" => {
                let value = op.get("value").ok_or_else(|| QidError::BadRequest {
                    message: "JSON Patch add missing 'value'".to_string(),
                })?;
                json_pointer_add(root, path, value.clone())?;
            }
            _ => {
                return Err(QidError::BadRequest {
                    message: format!("unsupported JSON Patch op: {op_type}"),
                });
            }
        }
    }
    Ok(())
}

fn json_pointer_remove(root: &mut Value, pointer: &str) -> QidResult<()> {
    if pointer.is_empty() || pointer == "/" {
        return Err(QidError::BadRequest {
            message: "JSON Pointer cannot remove root".to_string(),
        });
    }
    let parent_path = pointer.rfind('/').map(|i| &pointer[..i]).unwrap_or("");
    let key = json_pointer_unescape(pointer.rsplit('/').next().unwrap_or(""));
    let parent = json_pointer_get_mut(root, parent_path)?;
    match parent {
        Value::Object(map) => {
            map.remove(&key).ok_or_else(|| QidError::BadRequest {
                message: format!("JSON Patch remove: key '{key}' not found at '{parent_path}'"),
            })?;
        }
        Value::Array(arr) => {
            let idx: usize = key.parse().map_err(|_| QidError::BadRequest {
                message: format!("JSON Patch remove: invalid index '{key}'"),
            })?;
            if idx >= arr.len() {
                return Err(QidError::BadRequest {
                    message: format!("JSON Patch remove: index {idx} out of bounds"),
                });
            }
            arr.remove(idx);
        }
        _ => {
            return Err(QidError::BadRequest {
                message: "JSON Patch remove: parent is not object or array".to_string(),
            });
        }
    }
    Ok(())
}

fn json_pointer_add(root: &mut Value, pointer: &str, value: Value) -> QidResult<()> {
    if pointer.is_empty() {
        *root = value;
        return Ok(());
    }
    let parent_path = pointer.rfind('/').map(|i| &pointer[..i]).unwrap_or("");
    let key = json_pointer_unescape(pointer.rsplit('/').next().unwrap_or(""));
    if parent_path.is_empty() && key.is_empty() {
        *root = value;
        return Ok(());
    }
    let parent = json_pointer_get_mut(root, parent_path)?;
    match parent {
        Value::Object(map) => {
            map.insert(key, value);
        }
        Value::Array(arr) => {
            if key == "-" {
                arr.push(value);
            } else {
                let idx: usize = key.parse().map_err(|_| QidError::BadRequest {
                    message: format!("JSON Patch add: invalid index '{key}'"),
                })?;
                if idx > arr.len() {
                    return Err(QidError::BadRequest {
                        message: format!("JSON Patch add: index {idx} out of bounds"),
                    });
                }
                arr.insert(idx, value);
            }
        }
        _ => {
            return Err(QidError::BadRequest {
                message: "JSON Patch add: parent is not object or array".to_string(),
            });
        }
    }
    Ok(())
}

fn json_pointer_get_mut<'a>(root: &'a mut Value, pointer: &str) -> QidResult<&'a mut Value> {
    // Recursive descent through the JSON tree (avoids unsafe pointer
    // tricks that are needed for iterative navigation).
    if pointer.is_empty() {
        return Ok(root);
    }
    let Some(rest) = pointer.strip_prefix('/') else {
        return Err(QidError::BadRequest {
            message: format!("JSON Pointer must start with '/': {pointer}"),
        });
    };
    let (token_str, tail) = rest.split_once('/').unwrap_or((rest, ""));
    let decoded = json_pointer_unescape(token_str);
    let next_pointer = if tail.is_empty() {
        String::new()
    } else {
        format!("/{tail}")
    };
    match root {
        Value::Object(map) => {
            let child = map.get_mut(&decoded).ok_or_else(|| QidError::BadRequest {
                message: format!("JSON Pointer {pointer}: key '{decoded}' not found"),
            })?;
            if next_pointer.is_empty() {
                Ok(child)
            } else {
                json_pointer_get_mut(child, &next_pointer)
            }
        }
        Value::Array(arr) => {
            let idx: usize = decoded.parse().map_err(|_| QidError::BadRequest {
                message: format!("JSON Pointer {pointer}: invalid array index '{decoded}'"),
            })?;
            let child = arr.get_mut(idx).ok_or_else(|| QidError::BadRequest {
                message: format!("JSON Pointer {pointer}: index {idx} out of bounds"),
            })?;
            if next_pointer.is_empty() {
                Ok(child)
            } else {
                json_pointer_get_mut(child, &next_pointer)
            }
        }
        _ => Err(QidError::BadRequest {
            message: format!("JSON Pointer {pointer}: cannot index into scalar"),
        }),
    }
}

fn json_pointer_set(root: &mut Value, pointer: &str, value: Value) -> QidResult<()> {
    let target = json_pointer_get_mut(root, pointer)?;
    *target = value;
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON Merge Patch (RFC 7386)
// ---------------------------------------------------------------------------

/// Apply a JSON Merge Patch (RFC 7386) to a JSON value.
pub fn json_merge_patch_apply(root: &mut Value, patch: &Value) {
    match (root, patch) {
        (root @ &mut Value::Object(_), Value::Object(patch_map)) => {
            let root_map = root.as_object_mut().expect("checked above");
            let patch_keys: Vec<String> = patch_map.keys().cloned().collect();
            for key in patch_keys {
                let patch_val = &patch_map[&key];
                if patch_val.is_null() {
                    root_map.remove(&key);
                } else if root_map.contains_key(&key) {
                    json_merge_patch_apply(&mut root_map[&key], patch_val);
                } else {
                    root_map.insert(key, patch_val.clone());
                }
            }
        }
        (root, patch) => {
            *root = patch.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jcs_serialises_simple() {
        let v = json!({"b":2,"a":1});
        assert_eq!(jcs_stringify(&v), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn jcs_handles_nested() {
        let v = json!({"z":{"d":4,"c":3},"y":2});
        assert_eq!(jcs_stringify(&v), r#"{"y":2,"z":{"c":3,"d":4}}"#);
    }

    #[test]
    fn json_pointer_basic() {
        let v = json!({"foo": {"bar": [1,2,3]}});
        assert_eq!(json_pointer_get(&v, "/foo/bar/1").unwrap(), &json!(2));
    }

    #[test]
    fn json_pointer_not_found() {
        let v = json!({"a": 1});
        assert!(json_pointer_get(&v, "/b").is_err());
    }

    #[test]
    fn json_patch_roundtrip() {
        let mut v = json!({"a": 1, "b": 2});
        let patch = json!([
            {"op": "replace", "path": "/a", "value": 10},
            {"op": "remove", "path": "/b"}
        ]);
        json_patch_apply(&mut v, &patch).unwrap();
        assert_eq!(v, json!({"a": 10}));
    }

    #[test]
    fn json_merge_patch_updates() {
        let mut target = json!({"a": 1, "b": 2});
        let patch = json!({"a": 10, "c": 3});
        json_merge_patch_apply(&mut target, &patch);
        assert_eq!(target, json!({"a": 10, "b": 2, "c": 3}));
    }

    #[test]
    fn json_merge_patch_removes_null() {
        let mut target = json!({"a": 1, "b": 2});
        let patch = json!({"b": null});
        json_merge_patch_apply(&mut target, &patch);
        assert_eq!(target, json!({"a": 1}));
    }

    #[test]
    fn json_patch_add_to_array() {
        let mut v = json!([1, 2]);
        let patch = json!([{"op": "add", "path": "/-", "value": 3}]);
        json_patch_apply(&mut v, &patch).unwrap();
        assert_eq!(v, json!([1, 2, 3]));
    }
}
