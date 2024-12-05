#[cfg(test)]
mod tests {
    use pgsql_sdk::rewrite::rewrite_sql;

    #[test]
    fn test_rewrite_create_stmt() {
        let sql = "CREATE TABLE T1(column1 INT8 CIPHERTEXT NOT NULL, column2 VARCHAR);";
        let rewrite_sql = rewrite_sql(sql).unwrap();
        assert_eq!(rewrite_sql, "CREATE TABLE T1(column1 ENCRYPTED_INT64 CIPHERTEXT NOT NULL, column2 VARCHAR);");
    }
}