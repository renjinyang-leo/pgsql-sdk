use std::collections::HashMap;

use crate::error::{Result, Error};
use lazy_static::lazy_static;

lazy_static! {
    static ref ENCRYPTED_TYPE_KEYWORD: HashMap<&'static str, &'static str> = {
        let mut map = HashMap::new();
        map.insert("INT8", "ENCRYPTED_INT64");
        map.insert("VARCHAR", "ENCRYPTED_VARCHAR");
        map
    };
}

pub fn rewrite_create_stmt_sql(sql: &str) -> Result<String> {
    if let Some((_, columns_part)) = sql.split_once('(') {
        if let Some(columns_part) = columns_part.strip_suffix(')') {
            let columns = columns_part.split(',').map(|col_desc| col_desc.trim()).collect::<Vec<&str>>();
            let mut rewrite_failed = false;
            let modified_columns = columns.into_iter().map(|col_desc| {
                let parts = col_desc.split_whitespace().collect::<Vec<&str>>();
                if parts.len() >= 2 {
                    if parts.contains(&"CIPHERTEXT") {
                        for (original_type, encrypt_type) in ENCRYPTED_TYPE_KEYWORD.iter() {
                            if parts[1] == *original_type {
                                let mut new_parts = parts.clone();
                                new_parts[1] = *encrypt_type;
                                return new_parts.join(" ");
                            }
                        }
                    }
                } else {
                    rewrite_failed = true;
                }
                return col_desc.to_string();
            }).collect::<Vec<String>>();
            if rewrite_failed {
                return Err(Error::RewriteFailed);
            }
            return Ok(format!("CREATE TABLE {}({})", sql.split_whitespace().next().unwrap(), modified_columns.join(", ")));
        } else {
            return Err(Error::RewriteFailed);
        }
    }
    return Err(Error::RewriteFailed);
}