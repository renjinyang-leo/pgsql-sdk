use std::{collections::HashMap, ffi::{c_char, CString}, sync::Mutex};
use metadata::{ConnectInfo, CONN_INFO, TABLE_MATES, TableMeta};
mod metadata;
mod rewrite;
mod crypto;
mod error;

#[no_mangle]
pub extern "C" fn init(c_host: *const c_char, c_port: *const c_char, c_username: *const c_char, c_password: *const c_char, c_database: *const c_char) -> bool {
    if let Ok(conn_info) = ConnectInfo::new(c_host, c_port, c_username, c_password, c_database) {
        unsafe { CONN_INFO = Some(Box::new(conn_info)) };
        unsafe { TABLE_MATES = Some(Mutex::new(Box::new(HashMap::<String, Box<TableMeta>>::new()))) };
        return false;
    }
    false
}

#[no_mangle]
pub extern "C" fn rewrite(c_sql: *const c_char) -> *const c_char {
    if let Ok(sql) = unsafe { CString::from_raw(c_sql as *mut c_char) }.into_string() {
        if let Ok(rewrited_sql) = CString::new(sql) {
            return rewrited_sql.as_ptr();
        }
        return std::ptr::null();
    }
    return std::ptr::null();
}