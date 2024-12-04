use std::sync::Arc;

use crate::{error::{Error, Result}, metadata::TableMeta};
use pg_parse::ast::Node;

pub fn check_column_involve_encrypted_index(table_meta: Arc<TableMeta>, col_name: &str) -> Result<bool> {
    for col in &table_meta.encrypted_index_columns {
        if col.col_name == col_name {
            return Ok(true);
        }
    }
    return Ok(false);
}

pub fn rewrite_select_stmt_sql(parse_sql: &Node) -> Result<String> {
    match *parse_sql {
        Node::SelectStmt(ref stmt) => {
            todo!();
        },
        _ => return Err(Error::RewriteFailed)
    }
}