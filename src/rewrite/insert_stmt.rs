use std::collections::HashMap;

use crate::error::{Result, Error};
use pg_parse::ast::{ConstValue, List, Node, SelectStmt};
use regex::Regex;
use crate::metadata::*;
use crate::crypto::{int64_to_gore_ciphertext, varchar_to_gore_ciphertext, int64_to_aes_ciphertext, varchar_to_aes_ciphertext};

pub fn rewrite_insert_stmt_sql(parse_sql: &Node) -> Result<String> {
    match *parse_sql {
        Node::InsertStmt(ref stmt) => {
            let relname = stmt.relation.as_ref().unwrap().relname.clone().unwrap();
            let table_meta = get_table_meta(&relname)?;
            if table_meta.encrypted_columns.len() != 0 {
                let mut index_extend = String::new();
                let mut rewrite_sql = parse_sql.to_string();

                let mut encrypted_col_map: HashMap<usize, u32> = HashMap::new();
                for index_col in &table_meta.encrypted_columns {
                    encrypted_col_map.insert(index_col.attnum as usize, index_col.attypid);
                }
                
                if table_meta.encrypted_index_columns.len() != 0 {
                    index_extend += " EINDEX (";
                    let mut ciphertext_vec = Vec::<String>::new();
                    match stmt.select_stmt.as_ref().unwrap().as_ref() {
                        Node::SelectStmt(SelectStmt {
                            values_lists: Some(values_lists),
                            ..
                        }) => {
                            let values = &values_lists[0];
                            match values {
                                Node::List(List { items }) => {
                                    for index_col in &table_meta.encrypted_index_columns {
                                        match &items[index_col.attnum as usize - 1] {
                                            Node::A_Const(ConstValue::Integer(int64_value)) => {
                                                if index_col.attypid == 20 {
                                                    ciphertext_vec.push(int64_to_gore_ciphertext(*int64_value)?);
                                                }
                                            },
                                            Node::A_Const(ConstValue::String(varchar_value)) => {
                                                if index_col.attypid == 1043 {
                                                    ciphertext_vec.push(varchar_to_gore_ciphertext((*varchar_value).clone())?);
                                                }
                                            },
                                            _ => return Err(Error::RewriteFailed),
                                        }
                                    }
                                }
                                _ => return Err(Error::RewriteFailed),
                            }
                        }
                        _ => return Err(Error::RewriteFailed),
                    }

                    index_extend += &ciphertext_vec.join(",");
                    index_extend += ");"
                }

                let mut value_list = Vec::<String>::new();
                match stmt.select_stmt.as_ref().unwrap().as_ref() {
                    Node::SelectStmt(SelectStmt {
                        values_lists: Some(values_lists),
                        ..
                    }) => {
                        let values = &values_lists[0];
                        match values {
                            Node::List(List { items }) => {
                                for (index, item) in items.iter().enumerate() {
                                    if let Some(attpid) = encrypted_col_map.get(&(index + 1)) {
                                        match &item {
                                            Node::A_Const(ConstValue::Integer(int64_value)) => {
                                                if *attpid == 20 {
                                                    value_list.push(int64_to_aes_ciphertext(*int64_value)?);
                                                }
                                            },
                                            Node::A_Const(ConstValue::String(varchar_value)) => {
                                                if *attpid == 1043 {
                                                    value_list.push(varchar_to_aes_ciphertext(varchar_value)?);
                                                }
                                            },
                                            _ => return Err(Error::RewriteFailed),
                                        }
                                    } else {
                                        match &item {
                                            Node::A_Const(ConstValue::Integer(value)) => {
                                                value_list.push(value.to_string());
                                            },
                                            Node::A_Const(ConstValue::String(value)) => {
                                                value_list.push(value.clone());
                                            },
                                            Node::A_Const(ConstValue::Float(value)) => {
                                                value_list.push(value.clone());
                                            },
                                            Node::A_Const(ConstValue::Bool(value)) => {
                                                value_list.push(value.to_string());
                                            },
                                            _ => return Err(Error::RewriteFailed),
                                        }
                                    }
                                }

                            }
                            _ => return Err(Error::RewriteFailed),
                        }
                    }
                    _ => return Err(Error::RewriteFailed),
                }
                let regex = Regex::new(r"(?i)VALUES\s*\((.*?)\)").unwrap();
                if let Some(captures) = regex.captures(&rewrite_sql) {
                    let old_values = captures.get(1).map(|m| m.as_str()).unwrap();
                    let new_values = value_list.join(", ");
                    rewrite_sql = rewrite_sql.replace(old_values, &new_values);
                } else {
                    return Err(Error::RewriteFailed);
                }

                if table_meta.encrypted_index_columns.len() != 0 {
                    rewrite_sql += &index_extend;
                } else {
                    rewrite_sql += ";"
                }
                return Ok(rewrite_sql);
            }
            return Ok(parse_sql.to_string());
        },
        _ => return Err(Error::RewriteFailed)
    }
}