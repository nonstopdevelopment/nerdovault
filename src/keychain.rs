#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPolicy {
    UserPresence,
    BiometryCurrentSet,
}

impl AccessPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserPresence => "userPresence",
            Self::BiometryCurrentSet => "biometryCurrentSet",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "biometryCurrentSet" => Self::BiometryCurrentSet,
            _ => Self::UserPresence,
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::AccessPolicy;
    use crate::crypto;
    use anyhow::{anyhow, bail, Context, Result};
    use std::ffi::CString;
    use std::os::raw::{c_char, c_long, c_ulong, c_void};
    use std::ptr;

    type CFIndex = c_long;
    type CFOptionFlags = c_ulong;
    type OSStatus = i32;
    type CFTypeRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFDataRef = *const c_void;
    type CFDictionaryRef = *const c_void;
    type CFMutableDictionaryRef = *mut c_void;
    type SecAccessControlRef = *const c_void;

    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const ERR_SEC_SUCCESS: OSStatus = 0;
    const ERR_SEC_DUPLICATE_ITEM: OSStatus = -25299;
    const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;
    const K_SEC_ACCESS_CONTROL_USER_PRESENCE: CFOptionFlags = 1 << 0;
    const K_SEC_ACCESS_CONTROL_BIOMETRY_CURRENT_SET: CFOptionFlags = 1 << 3;

    const SERVICE: &str = "dev.nonstop.nerdovault";
    const ACCOUNT: &str = "master-key";

    #[repr(C)]
    struct CFDictionaryKeyCallBacks {
        version: CFIndex,
        retain: *const c_void,
        release: *const c_void,
        copy_description: *const c_void,
        equal: *const c_void,
        hash: *const c_void,
    }

    #[repr(C)]
    struct CFDictionaryValueCallBacks {
        version: CFIndex,
        retain: *const c_void,
        release: *const c_void,
        copy_description: *const c_void,
        equal: *const c_void,
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
        static kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;
        static kCFBooleanTrue: CFTypeRef;

        fn CFStringCreateWithCString(
            alloc: CFTypeRef,
            c_str: *const c_char,
            encoding: u32,
        ) -> CFStringRef;
        fn CFDataCreate(alloc: CFTypeRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
        fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
        fn CFDataGetLength(data: CFDataRef) -> CFIndex;
        fn CFDictionaryCreateMutable(
            allocator: CFTypeRef,
            capacity: CFIndex,
            key_callbacks: *const CFDictionaryKeyCallBacks,
            value_callbacks: *const CFDictionaryValueCallBacks,
        ) -> CFMutableDictionaryRef;
        fn CFDictionarySetValue(dict: CFMutableDictionaryRef, key: CFTypeRef, value: CFTypeRef);
        fn CFRelease(cf: CFTypeRef);
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecClass: CFStringRef;
        static kSecClassGenericPassword: CFStringRef;
        static kSecAttrService: CFStringRef;
        static kSecAttrAccount: CFStringRef;
        static kSecValueData: CFStringRef;
        static kSecReturnData: CFStringRef;
        static kSecMatchLimit: CFStringRef;
        static kSecMatchLimitOne: CFStringRef;
        static kSecAttrAccessControl: CFStringRef;
        static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
        static kSecUseOperationPrompt: CFStringRef;

        fn SecAccessControlCreateWithFlags(
            allocator: CFTypeRef,
            protection: CFTypeRef,
            flags: CFOptionFlags,
            error: *mut CFTypeRef,
        ) -> SecAccessControlRef;
        fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
        fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
        fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;
    }

    pub struct Keychain;

    impl Keychain {
        pub fn load_or_create_master_key(policy: AccessPolicy) -> Result<Vec<u8>> {
            match Self::read_master_key("Unlock Nerdovault") {
                Ok(key) => Ok(key),
                Err(error) if is_item_not_found(&error) => {
                    let key = crypto::generate_master_key();
                    Self::store_master_key(&key, policy)?;
                    Ok(key.to_vec())
                }
                Err(error) => Err(error),
            }
        }

        pub fn read_master_key(prompt: &str) -> Result<Vec<u8>> {
            unsafe {
                let dict = base_query()?;
                let prompt = cf_string(prompt)?;
                CFDictionarySetValue(dict.0, kSecReturnData, kCFBooleanTrue);
                CFDictionarySetValue(dict.0, kSecMatchLimit, kSecMatchLimitOne);
                CFDictionarySetValue(dict.0, kSecUseOperationPrompt, prompt.0);

                let mut result: CFTypeRef = ptr::null();
                let status = SecItemCopyMatching(dict.0 as CFDictionaryRef, &mut result);
                if status != ERR_SEC_SUCCESS {
                    return keychain_error("read master key", status);
                }
                if result.is_null() {
                    bail!("Keychain returned an empty master key");
                }

                let data = OwnedCf(result);
                let len = CFDataGetLength(data.0 as CFDataRef);
                let ptr = CFDataGetBytePtr(data.0 as CFDataRef);
                if ptr.is_null() || len <= 0 {
                    bail!("Keychain returned invalid master key data");
                }
                let bytes = std::slice::from_raw_parts(ptr, len as usize).to_vec();
                if bytes.len() != crypto::MASTER_KEY_LEN {
                    bail!("Keychain master key has invalid length");
                }
                Ok(bytes)
            }
        }

        pub fn master_key_exists() -> Result<bool> {
            unsafe {
                let dict = base_query()?;
                CFDictionarySetValue(dict.0, kSecMatchLimit, kSecMatchLimitOne);
                let status = SecItemCopyMatching(dict.0 as CFDictionaryRef, ptr::null_mut());
                match status {
                    ERR_SEC_SUCCESS => Ok(true),
                    ERR_SEC_ITEM_NOT_FOUND => Ok(false),
                    _ => keychain_error("check master key", status),
                }
            }
        }

        fn store_master_key(
            key: &[u8; crypto::MASTER_KEY_LEN],
            policy: AccessPolicy,
        ) -> Result<()> {
            unsafe {
                let dict = base_query()?;
                let data = cf_data(key)?;
                let access = access_control(policy)?;
                CFDictionarySetValue(dict.0, kSecValueData, data.0);
                CFDictionarySetValue(dict.0, kSecAttrAccessControl, access.0);

                let status = SecItemAdd(dict.0 as CFDictionaryRef, ptr::null_mut());
                match status {
                    ERR_SEC_SUCCESS => Ok(()),
                    ERR_SEC_DUPLICATE_ITEM => Ok(()),
                    _ => keychain_error("store master key", status),
                }
            }
        }

        #[allow(dead_code)]
        pub fn delete_master_key() -> Result<()> {
            unsafe {
                let dict = base_query()?;
                let status = SecItemDelete(dict.0 as CFDictionaryRef);
                match status {
                    ERR_SEC_SUCCESS | ERR_SEC_ITEM_NOT_FOUND => Ok(()),
                    _ => keychain_error("delete master key", status),
                }
            }
        }
    }

    fn is_item_not_found(error: &anyhow::Error) -> bool {
        error.to_string().contains("OSStatus -25300")
    }

    unsafe fn base_query() -> Result<OwnedDict> {
        let dict = OwnedDict::new()?;
        let service = cf_string(SERVICE)?;
        let account = cf_string(ACCOUNT)?;
        CFDictionarySetValue(dict.0, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(dict.0, kSecAttrService, service.0);
        CFDictionarySetValue(dict.0, kSecAttrAccount, account.0);
        Ok(dict)
    }

    unsafe fn access_control(policy: AccessPolicy) -> Result<OwnedCf> {
        let flags = match policy {
            AccessPolicy::UserPresence => K_SEC_ACCESS_CONTROL_USER_PRESENCE,
            AccessPolicy::BiometryCurrentSet => K_SEC_ACCESS_CONTROL_BIOMETRY_CURRENT_SET,
        };
        let mut error: CFTypeRef = ptr::null();
        let access = SecAccessControlCreateWithFlags(
            ptr::null(),
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &mut error,
        );
        if !error.is_null() {
            CFRelease(error);
        }
        if access.is_null() {
            bail!("failed to create Keychain access control");
        }
        Ok(OwnedCf(access))
    }

    unsafe fn cf_string(value: &str) -> Result<OwnedCf> {
        let c_value = CString::new(value).context("string contains null byte")?;
        let cf =
            CFStringCreateWithCString(ptr::null(), c_value.as_ptr(), K_CF_STRING_ENCODING_UTF8);
        if cf.is_null() {
            bail!("failed to create CoreFoundation string");
        }
        Ok(OwnedCf(cf))
    }

    unsafe fn cf_data(bytes: &[u8]) -> Result<OwnedCf> {
        let cf = CFDataCreate(ptr::null(), bytes.as_ptr(), bytes.len() as CFIndex);
        if cf.is_null() {
            bail!("failed to create CoreFoundation data");
        }
        Ok(OwnedCf(cf))
    }

    fn keychain_error<T>(operation: &str, status: OSStatus) -> Result<T> {
        Err(anyhow!(
            "Keychain {operation} failed with OSStatus {status}"
        ))
    }

    struct OwnedCf(CFTypeRef);

    impl Drop for OwnedCf {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0) };
            }
        }
    }

    struct OwnedDict(CFMutableDictionaryRef);

    impl OwnedDict {
        unsafe fn new() -> Result<Self> {
            let dict = CFDictionaryCreateMutable(
                ptr::null(),
                0,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            );
            if dict.is_null() {
                bail!("failed to create CoreFoundation dictionary");
            }
            Ok(Self(dict))
        }
    }

    impl Drop for OwnedDict {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0 as CFTypeRef) };
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos::Keychain;

#[cfg(not(target_os = "macos"))]
pub struct Keychain;

#[cfg(not(target_os = "macos"))]
impl Keychain {
    pub fn load_or_create_master_key(_policy: AccessPolicy) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("Nerdovault v1 requires macOS Keychain")
    }

    pub fn read_master_key(_prompt: &str) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("Nerdovault v1 requires macOS Keychain")
    }

    pub fn master_key_exists() -> anyhow::Result<bool> {
        Ok(false)
    }
}
