use crate::sectors;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};

pub struct Session {
    pub connection: Option<TcpStream>,
    ip: String,
    port: u16,
}

impl Session {
    fn new(connection: Option<TcpStream>, ip: String, port: u16) -> Self {
        Session {
            connection,
            ip,
            port,
        }
    }

    pub fn recv(&mut self) -> Vec<u8> {
        let mut dat_len = [0; 8];
        match self.connection.as_mut().unwrap().read_exact(&mut dat_len) {
            Ok(_) => {
                let int_len = sectors::bytes_to_int(&dat_len);
                if int_len > 65535 || int_len == 0 {
                    return vec![];
                }
                let mut full_pkg = vec![0; int_len as usize];
                match self.connection.as_mut().unwrap().read_exact(&mut full_pkg) {
                    Ok(_) => full_pkg,
                    Err(err) => {
                        vec![]
                    }
                }
            }
            Err(err) => {
                vec![]
            }
        }
    }

    pub fn send(&mut self, data: &[u8]) {
        let data = sectors::write_sector(data);
        self.connection.as_mut().unwrap().write_all(&data).unwrap();
    }

    pub fn shutdown(&mut self) {
        self.connection
            .as_mut()
            .unwrap()
            .shutdown(Shutdown::Both)
            .ok();
    }
}

pub fn bind(ip: String, port: u16) -> TcpListener {
    let local_addr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();
    let listener = TcpListener::bind(local_addr).unwrap();
    listener
}

pub fn accept(socket: &TcpListener) -> Session {
    let (conn, addr) = socket.accept().unwrap();
    let ip = addr.ip().to_string();
    let port = addr.port();
    Session::new(Some(conn), ip, port)
}
