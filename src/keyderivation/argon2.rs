use argon2::{
    password_hash::{PasswordHasher, Salt, SaltString},
    Argon2,
};
use std::convert::TryFrom;

pub fn password_to_rk(password: Vec<u8>, salt: Vec<u8>) -> String {
    let params = argon2::Params {
        m_cost: 37000,
        t_cost: 2,
        p_cost: 1,
        output_size: 32,
        version: argon2::Version::default(),
    };
    let argon2 = Argon2::default();
    let salt = SaltString::new(&base64::encode(salt)).unwrap();
    let hash = argon2
    .hash_password(
        &password,
        None,
        params,
        Salt::try_from(salt.as_ref()).unwrap(),
    )
    .unwrap();
    return hash.to_string();
}