use crate::error::{Result, Error};
use pg_parse::ast::Node;

pub fn rewrite_select_stmt_sql(parse_sql: &Node) -> Result<String> {
    match *parse_sql {
        Node::SelectStmt(ref _stmt) => {
            
        },
        _ => return Err(Error::RewriteFailed)
    }
    Ok(parse_sql.to_string())
}