use crate::keys::one_time_prekey::OneTimePreKeyGroupPublic;

/// Represents the public information of a user required for the Signal protocol.
///
/// This struct contains the user's unique identifier, display name, and the public keys
/// necessary for establishing secure communication:
///
/// - `ik`: The user's identity public key (32 bytes).
/// - `spk`: The user's signed pre-key (32 bytes).
/// - `opk`: The user's one-time pre-key group public information.
///
/// # Fields
/// - `id`: Unique identifier for the user.
/// - `name`: Human-readable name of the user.
/// - `ik`: Identity public key (used to verify long-term ownership).
/// - `spk`: Signed pre-key (ephemeral key signed by `ik`).
/// - `opk`: One-time pre-key group used for forward secrecy.
pub struct UserPublicInfo {
    pub id: String,
    pub name: String,
    pub ik: [u8; 32],
    pub spk: [u8; 32],
    pub opk: OneTimePreKeyGroupPublic,
}
