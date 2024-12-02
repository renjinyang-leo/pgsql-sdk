use std::{collections::HashMap, ffi::{c_char, CString}, fmt::format, sync::{Arc, Mutex}};
use postgres::Client;

use crate::error::{Result, Error};

struct Column {
    col_name: String,
    attnum: u32,
    attypid: u32
}

impl Column {
    fn new(col_name: &str, attnum: u32, attypid: u32) -> Self {
        Self {
            col_name: col_name.to_string(),
            attnum,
            attypid
        }
    }
}

pub struct TableMeta {
    table_name: String,
    encrypted_columns: Vec<Column>,
    encrypted_index_columns: Vec<Column>
}

impl TableMeta {
    fn new(table_name: String, encrypted_columns: Vec<Column>, encrypted_index_columns: Vec<Column>) -> Self {
        Self{
            table_name,
            encrypted_columns,
            encrypted_index_columns
        }
    }
}

pub struct ConnectInfo {
    host: String,
    port: String,
    username: String,
    password: String,
    database: String
}

impl ConnectInfo {
    pub fn new(c_host: *const c_char, c_port: *const c_char, c_username: *const c_char, c_password: *const c_char, c_database: *const c_char) -> Result<Self> {
        let host = unsafe { CString::from_raw(c_host as *mut c_char) }.into_string()?;
        let port = unsafe { CString::from_raw(c_port as *mut c_char) }.into_string()?;
        let username = unsafe { CString::from_raw(c_username as *mut c_char) }.into_string()?;
        let password = unsafe { CString::from_raw(c_password as *mut c_char) }.into_string()?;
        let database = unsafe { CString::from_raw(c_database as *mut c_char) }.into_string()?;

        return Ok(
            Self{
                host,
                port,
                username,
                password,
                database
            }
        )
    }
}


pub static mut TABLE_MATES: Option<Mutex<Box<HashMap<String, Box<TableMeta>>>>> = None;
pub static mut CONN_INFO: Option<Box<ConnectInfo>> = None;


pub fn update_metadata(table_name: &str) -> Result<()> {
    match unsafe { TABLE_MATES.as_ref() } {
        Some(mutex_table) => {
            let mut table = mutex_table.lock().unwrap();
            let conn_info = unsafe { CONN_INFO.as_ref().unwrap() };

            let mut client = Client::connect(
                &format!("postgresql://{}:{}@{}:{}/{}", conn_info.username, conn_info.password, conn_info.host, conn_info.port, conn_info.database),
                postgres::NoTls,
            )?;

            let col_query_sql = format!("SELECT attname,attnum,atttypid FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = '{}') AND attnum > 0 AND attencryption = true;", table_name);
            let index_col_query_sql = format!("SELECT att.attname,att.atttypid FROM pg_attribute att JOIN pg_index idx ON att.attrelid = idx.indrelid AND att.attnum = ANY (idx.indkey) JOIN pg_class cls ON att.attrelid = cls.oid WHERE cls.relname = '{}' AND att.attencryption = true AND att.attnum > 0;", table_name);
            let mut result = client.query(&col_query_sql, &[])?;


            let mut encrypted_columns = Vec::new();
            let mut encrypted_index_columns = Vec::new();


            for row in result {
                let col_name: &str = row.get(0);
                let attnum: u32 = row.get(1);
                let attypid: u32 = row.get(2);
                let col = Column::new(col_name, attnum, attypid);
                encrypted_columns.push(col);
            }

            result = client.query(&index_col_query_sql, &[])?;
            for row in result {
                let col_name: &str = row.get(1);
                let attypid: u32 = row.get(2);
                let col = Column::new(col_name, 0, attypid);
                encrypted_index_columns.push(col);
            }

            table.insert(table_name.to_string(), Box::new(TableMeta::new(table_name.to_string(), encrypted_columns, encrypted_index_columns)));
        },
        None => return Err(Error::NotInitialize),
    };

    Ok(())
}