use crate::keys::one_time_prekey::OneTimePreKeyGroupPublic;

pub struct UserPublicInfo {
    pub id: String,
    pub name: String,
    pub ik: [u8; 32],
    pub spk: [u8; 32],
    pub opk: OneTimePreKeyGroupPublic,
}
