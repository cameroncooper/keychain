use plist::{Dictionary, Value};
use zeroize::Zeroize;

pub(crate) fn zeroize_plist_dictionary(dictionary: &mut Dictionary) {
    for value in dictionary.values_mut() {
        zeroize_plist_value(value);
    }
}

fn zeroize_plist_value(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Data(value) => value.zeroize(),
        Value::Array(values) => {
            for value in values {
                zeroize_plist_value(value);
            }
        }
        Value::Dictionary(dictionary) => zeroize_plist_dictionary(dictionary),
        _ => {}
    }
}
