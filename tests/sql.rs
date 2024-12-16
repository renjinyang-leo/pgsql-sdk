#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::iter;

    use pgsql_sdk::rewrite::rewrite_sql;
    use pgsql_sdk::crypto::{int64_to_gore_ciphertext, decode_ciphertext_int64, ciphertext_compare, varchar_to_gore_ciphertext, decode_ciphertext_varchar};
    use rand::Rng;

    fn random_string() -> String {
        let length = rand::thread_rng().gen_range(1..11);
        let mut rng = rand::thread_rng();
        iter::repeat(())
       .map(|()| {
            let byte = rng.sample(rand::distributions::Alphanumeric);
            byte as char
        })
       .take(length)
       .collect()
    }

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

    #[test]
    fn test_gore_varchar() {
        for _ in 0..1000 {
            let string_1 = random_string();
            let string_2 = random_string();
            let ciphertext_str_1 = varchar_to_gore_ciphertext(string_1.clone()).unwrap();
            let ciphertext_str_2 = varchar_to_gore_ciphertext(string_2.clone()).unwrap();

            let ciphertext_1 = decode_ciphertext_varchar(&ciphertext_str_1).unwrap();
            let ciphertext_2 = decode_ciphertext_varchar(&ciphertext_str_2).unwrap();

            let expect = if string_1.cmp(&string_2) == Ordering::Equal {
                0
            } else if string_1.cmp(&string_2) == Ordering::Greater {
                1
            } else {
                -1
            };

            assert_eq!(expect, ciphertext_compare(&ciphertext_1.buf, &ciphertext_2.buf).unwrap());
        }
    }
}