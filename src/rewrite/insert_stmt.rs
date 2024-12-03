use crate::error::{Result, Error};
use pg_parse::ast::Node;

pub fn rewrite_insert_stmt_sql(parse_sql: &Node) -> Result<String> {
    match *parse_sql {
        Node::InsertStmt(ref _stmt) => {
            
        },
        _ => return Err(Error::RewriteFailed)
    }
    Ok(parse_sql.to_string())
}