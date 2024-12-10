#[cfg(test)]
mod tests {
    use pgsql_sdk::rewrite::rewrite_sql;
    use pgsql_sdk::crypto::{int64_to_gore_ciphertext, decode_ciphertext_int64, ciphertext_compare};
    use rand::Rng;

    #[test]
    fn test_rewrite_create_stmt() {
        let sql = "CREATE TABLE T1(column1 INT8 CIPHERTEXT NOT NULL, column2 VARCHAR);";
        let rewrite_sql = rewrite_sql(sql).unwrap();
        assert_eq!(rewrite_sql, "CREATE TABLE T1(column1 ENCRYPTED_INT64 CIPHERTEXT NOT NULL, column2 VARCHAR);");
    }

    #[test]
    fn test_gore_int64() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let num_1: i64 = rng.gen();
            let num_2: i64 = rng.gen();
            let ciphertext_str_1 = int64_to_gore_ciphertext(num_1).unwrap();
            let ciphertext_str_2 = int64_to_gore_ciphertext(num_2).unwrap();

            let ciphertext_1 = decode_ciphertext_int64(&ciphertext_str_1).unwrap();
            let ciphertext_2 = decode_ciphertext_int64(&ciphertext_str_2).unwrap();
            let expect= if num_1 == num_2 {
                0
            } else if num_1 < num_2 {
                -1
            } else {
                1
            };
            assert_eq!(expect, ciphertext_compare(&ciphertext_1.buf, &ciphertext_2.buf).unwrap());
        }
    }
}