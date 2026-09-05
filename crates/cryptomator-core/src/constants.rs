//! Vault layout constants, ported from cryptofs `common/Constants.java`.
pub const VAULT_VERSION: u32 = 8;
pub const BACKUP_SUFFIX: &str = ".bkup";
pub const DATA_DIR_NAME: &str = "d";
pub const ROOT_DIR_ID: &str = "";
pub const RECOVERY_DIR_ID: &str = "recovery";
pub const CRYPTOMATOR_FILE_SUFFIX: &str = ".c9r";
pub const DEFLATED_FILE_SUFFIX: &str = ".c9s";
pub const INUSE_FILE_SUFFIX: &str = ".c9u";
pub const DIR_FILE_NAME: &str = "dir.c9r";
pub const SYMLINK_FILE_NAME: &str = "symlink.c9r";
pub const CONTENTS_FILE_NAME: &str = "contents.c9r";
pub const INFLATED_FILE_NAME: &str = "name.c9s";
pub const DIR_ID_BACKUP_FILE_NAME: &str = "dirid.c9r";
pub const MAX_SYMLINK_LENGTH: usize = 32767;
pub const MAX_DIR_ID_LENGTH: usize = 36;
pub const MAX_CIPHER_NAME_LENGTH: usize = 220;
pub const MIN_CIPHER_NAME_LENGTH: usize = 28;
pub const MAX_ADDITIONAL_PATH_LENGTH: usize = 48;
pub const RECOVERY_DIR_NAME: &str = "LOST+FOUND";
pub const INUSE_CLEARTEXT_SIZE: usize = 1000;
/// File names used by the desktop app (`common/Constants.java`).
pub const MASTERKEY_FILENAME: &str = "masterkey.cryptomator";
pub const VAULTCONFIG_FILENAME: &str = "vault.cryptomator";
pub const DEFAULT_KEY_ID: &str = "masterkeyfile:masterkey.cryptomator";
