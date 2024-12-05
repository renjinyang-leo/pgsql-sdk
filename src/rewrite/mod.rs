mod create_stmt;
mod insert_stmt;
mod select_stmt;

use pg_parse::ast::Node;
use regex::Regex;
use crate::error::{Error, Result};

pub fn rewrite_sql(sql: &str) -> Result<String> {
    let check_create = Regex::new(r"(?i)create table").unwrap();
    let check_sql_num = Regex::new(r";").unwrap();
    if check_create.is_match(sql) {
        let v = check_sql_num.split(sql).collect::<Vec<&str>>();
        if v.len() == 2 {
            let rewrite_sql = create_stmt::rewrite_create_stmt_sql(v[0])?;
            return Ok(rewrite_sql);
        }
        return Err(Error::RewriteFailed);
    } else {
        let parse_sql_set = pg_parse::parse(sql)?;
        let mut rewrite_sql_set = String::new();
        for parse_sql in &parse_sql_set {
            let rewrite_sql;
            if matches!(*parse_sql, Node::InsertStmt(_)) {
                rewrite_sql = insert_stmt::rewrite_insert_stmt_sql(parse_sql)?;
            } else if matches!(*parse_sql, Node::SelectStmt(_)) {
                rewrite_sql = select_stmt::rewrite_select_stmt_sql(parse_sql)?;
            } else {
                rewrite_sql = parse_sql.to_string();
            }
            rewrite_sql_set += &rewrite_sql;
        }
        Ok(rewrite_sql_set)   
    }
}