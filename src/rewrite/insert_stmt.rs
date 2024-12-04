use crate::error::{Result, Error};
use pg_parse::ast::{ConstValue, List, Node, SelectStmt};
use crate::metadata::*;
use crate::crypto::encode_ciphertext;

pub fn rewrite_insert_stmt_sql(parse_sql: &Node) -> Result<String> {
    match *parse_sql {
        Node::InsertStmt(ref stmt) => {
            let relname = stmt.relation.as_ref().unwrap().relname.clone().unwrap();
            let table_meta = get_table_meta(&relname)?;
            if table_meta.encrypted_columns.len() != 0 {
                let mut index_extend = String::new();
                let mut rewrite_sql = parse_sql.to_string().strip_suffix(";").unwrap().to_string();
                
                if table_meta.encrypted_index_columns.len() != 0 {
                    index_extend += " INDEX(";
                    let mut ciphertext = Vec::<String>::new();
                    if let Some(cols) = stmt.cols.as_ref() {
                        if cols.len() == 0 {
                            return Err(Error::RewriteFailed);
                        }
                    } else {
                        return Err(Error::RewriteFailed);
                    }
                    match stmt.select_stmt.as_ref().unwrap().as_ref() {
                        Node::SelectStmt(SelectStmt {
                            values_lists: Some(values_lists),
                            ..
                        }) => {
                            let values = &values_lists[0];
                            match values {
                                Node::List(List { items }) => {
                                    for index_col in &table_meta.encrypted_index_columns {
                                        match &items[index_col.attnum as usize] {
                                            Node::A_Const(ConstValue::Integer(int64_value)) => {
                                                if index_col.attypid == 20 {
                                                    ciphertext.push(encode_ciphertext(*int64_value)?);
                                                }
                                            },
                                            Node::A_Const(ConstValue::String(varchar_value)) => {
                                                if index_col.attypid == 1043 {
                                                    ciphertext.push(encode_ciphertext((*varchar_value).clone())?);
                                                }
                                            },
                                            _ => return Err(Error::RewriteFailed),
                                        }
                                    }

                                    for index_col in &table_meta.encrypted_columns {
                                        match &items[index_col.attnum as usize] {
                                            Node::A_Const(ConstValue::Integer(int64_value)) => {
                                                if index_col.attypid == 20 {
                                                    todo!("AES encrypt the data in the columns");
                                                }
                                            },
                                            Node::A_Const(ConstValue::String(varchar_value)) => {
                                                if index_col.attypid == 1043 {
                                                    todo!("AES encrypt the data in the columns");
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

                    index_extend += &ciphertext.join(",");
                    index_extend += ");"
                }
                rewrite_sql += &index_extend;
                return Ok(rewrite_sql);
            }
            return Ok(parse_sql.to_string());
        },
        _ => return Err(Error::RewriteFailed)
    }
}