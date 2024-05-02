use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt};
use aes::Aes256;

pub fn pkcs7padding(data: Vec<u8>, block_length: usize) -> Vec<u8> {
    let padding_size = block_length - (data.len() % block_length);
    let mut padded_data = data.to_vec();
    padded_data.extend(vec![padding_size as u8; padding_size]);
    padded_data
}

pub fn pkcs7unpadding(data: Vec<u8>) -> Vec<u8> {
    let data_len = data.len();
    let padding_length = data[data_len - 1] as usize;
    data[0..data_len - padding_length].to_vec()
}

pub fn encrypt(_aes: &Aes256, data: &Vec<u8>) -> Vec<u8> {
    let mut encrypted: Vec<u8> = Vec::new();
    let data = pkcs7padding(data.to_vec(), 16);
    for chunk in data.chunks_exact(16) {
        let block = GenericArray::from_slice(chunk);
        let mut mut_block = block.clone();
        _aes.encrypt_block(&mut mut_block);
        encrypted.extend_from_slice(mut_block.as_slice());
    }
    encrypted
}

pub fn decrypt(_aes: &Aes256, data: Vec<u8>) -> Vec<u8> {
    let mut decrypted: Vec<u8> = Vec::new();
    for chunk in data.chunks_exact(16) {
        let block = GenericArray::clone_from_slice(chunk);
        let mut mut_block = block.clone();
        _aes.decrypt_block(&mut mut_block);
        decrypted.extend_from_slice(mut_block.as_slice());
    }
    pkcs7unpadding(decrypted)
}
