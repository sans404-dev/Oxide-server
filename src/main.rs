#[macro_use]
extern crate log;

use env_logger::Builder;
use log::LevelFilter;
use rand;
use rand::RngCore;
use std::io;
use std::io::Write;
use std::thread;

mod aes_func;
mod sectors;
mod session_level;

use aes::cipher::{generic_array::GenericArray, KeyInit};
use aes::Aes256;
use generic_array::typenum::U32;
use rsa::pkcs8::DecodePublicKey;
use rsa::{traits::PublicKeyParts, Pkcs1v15Encrypt, RsaPublicKey};

use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::sync::Mutex;

struct User {
    session: session_level::Session,
    username: Option<String>,
    sector_num: i32,
    session_key: Option<Aes256>,
}

impl User {
    pub fn new(session: session_level::Session) -> Self {
        Self {
            session,
            username: None,
            sector_num: -1,
            session_key: None,
        }
    }

    pub fn recv(&mut self) -> Vec<u8> {
        let mut data = self.session.recv();
        if let Some(session_key) = &self.session_key {
            data = aes_func::decrypt(session_key, data);
        }
        data
    }

    pub fn send(&mut self, mut data: Vec<u8>) {
        if let Some(session_key) = &self.session_key {
            data = aes_func::encrypt(session_key, &data);
        }
        self.session.send(&data);
    }

    pub fn sendarr(&mut self, data: Vec<Vec<&[u8]>>) {
        let data = sectors::write_sectors(data);
        self.send(data);
    }

    fn user_thread(&mut self) {
        dbg!("{:?}", &self.session.connection);
        let mut users = sectors::SectorsType::new(Some("users.txt".to_string()), None);
        let mut polylogs = sectors::SectorsType::new(Some("polylogs.txt".to_string()), None);
        users.load().unwrap();
        polylogs.load().unwrap();
        loop {
            let data = self.recv();
            if !data.is_empty() {
                if !self.session_key.is_some() {
                    let data = &sectors::read_sectors(data);
                    let rsa_key = RsaPublicKey::from_public_key_pem(&data[0]).unwrap();
                    dbg!(&data);
                    dbg!("{:?}", &rsa_key.size() * 8);
                    dbg!("{}", data[1].len());
                    if (&rsa_key.size() * 8 == 1024) && (data[1].len() <= 100) {
                        info!("starting registration");
                        let mut rng = rand::thread_rng();
                        let mut bytes_key = [0u8; 32];
                        rng.fill_bytes(&mut bytes_key);
                        info!("i think... random 32 bytes will be {:?}", &bytes_key);
                        let enc_key = rsa_key
                            .encrypt(&mut rng, Pkcs1v15Encrypt, &bytes_key)
                            .unwrap();
                        info!("sharing session key {:?}", &enc_key);
                        self.send(enc_key);
                        self.session_key =
                            Some(Aes256::new(GenericArray::<u8, U32>::from_slice(&bytes_key)));
                        self.username = Some(data[1].clone());
                        let user_secnum = users.find(1, data[1].as_bytes());
                        dbg!("{}", &user_secnum);

                        if user_secnum == -1 {
                            users.add(vec![vec![data[0].as_bytes()], vec![data[1].as_bytes()]]);
                            users.save().unwrap();
                        }

                        self.sector_num = users.find(1, data[1].as_bytes());
                        if rsa_key
                            != RsaPublicKey::from_public_key_pem(
                                std::str::from_utf8(&users.getdat(self.sector_num as u32, 0))
                                    .unwrap(),
                            )
                            .unwrap()
                        {
                            warn!("HACKER ATTACK");
                            self.send(vec![1]);
                            self.session.shutdown();
                            break;
                        }
                        self.send(vec![0]);
                        dbg!("{:?}", &self.session_key);
                        dbg!("{:?}", &self.username);
                    } else {
                        self.session.shutdown();
                    }
                } else {
                    let data = &sectors::read_sectors_b(data);
                    if data[0] == b"0" {
                        let chatname = &data[1];
                        let chathash = &data[2];
                        if polylogs.findbin(0, &chatname) == -1 {
                            polylogs.add(vec![vec![chatname], vec![chathash]]);
                            polylogs.save().unwrap();
                            self.send(vec![0]);
                        } else {
                            self.send(vec![1]);
                        }
                    }
                    else if data[0] == b"1" {
                        let chatname = &data[1];
                        let chathash = &data[2];
                        let chatnum = polylogs.findbin(0, &chatname);
                        dbg!("{}", &chatnum);
                        if chatnum != -1 && &chatname.len() < &64 {
                            if polylogs.getdat(chatnum as u32, 1) == chathash.to_vec() {
                                dbg!("stage1");
                                let usrname = self.username.as_ref().unwrap().as_str().as_bytes().to_owned();
                                dbg!("stage2");
                                if !sectors::read_sectors_b(polylogs.getdat(chatnum as u32,2)).contains(&usrname) {
                                    dbg!("stage3");
                                    polylogs.add_to_field(chatnum as u32, 2, sectors::write_sector(&usrname));
                                    polylogs.save().unwrap();
                                    dbg!("stage4");
                                    self.send(vec![0]);
                                } else {
                                    self.send(vec![3]);
                                }
                            } else {
                                self.send(vec![2]);
                                dbg!("2");
                            }
                        } else {
                            dbg!("1");
                            self.send(vec![1]);
                        }
                    }
                }
            } else {
                info!("Client disconnected\n{:?}", self.session.connection);
                self.session.shutdown();
                break;
            }
        }
    }
}

fn main() {
    Builder::new().filter_level(LevelFilter::max()).init();
    info!("Welcome to test server :)");
    let binder = session_level::bind("127.0.0.1".to_string(), 4444);
    loop {
        let session = session_level::accept(&binder);
        info!("{:?}", &session.connection);
        let mut client = User::new(session);
        thread::spawn(move || {
            info!("{:?}", thread::current());
            client.user_thread();
        });
    }
}
