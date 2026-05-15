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
    use base64::prelude::*;
    use block::ConcreteBlock;
    use objc::runtime::{Object, BOOL, YES};
    use objc::{class, msg_send, sel, sel_impl};
    use std::ffi::CString;
    use std::os::raw::{c_char, c_long, c_void};
    use std::ptr;
    use std::sync::mpsc;

    type CFIndex = c_long;
    type OSStatus = i32;
    type CFTypeRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFDataRef = *const c_void;
    type CFDictionaryRef = *const c_void;
    type CFMutableDictionaryRef = *mut c_void;

    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const ERR_SEC_SUCCESS: OSStatus = 0;
    const ERR_SEC_DUPLICATE_ITEM: OSStatus = -25299;
    const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;
    const NS_UTF8_STRING_ENCODING: usize = 4;
    const LA_POLICY_DEVICE_OWNER_AUTHENTICATION_WITH_BIOMETRICS: isize = 1;
    const LA_POLICY_DEVICE_OWNER_AUTHENTICATION: isize = 2;

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

        fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
        fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
        fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;
    }

    #[link(name = "Foundation", kind = "framework")]
    extern "C" {}

    #[link(name = "LocalAuthentication", kind = "framework")]
    extern "C" {}

    pub struct Keychain;

    impl Keychain {
        pub fn authenticate(policy: AccessPolicy, reason: &str) -> Result<Option<String>> {
            authenticate(policy, reason)
        }

        pub fn load_or_create_master_key(_policy: AccessPolicy) -> Result<Vec<u8>> {
            match Self::read_master_key() {
                Ok(key) => Ok(key),
                Err(error) if is_item_not_found(&error) => {
                    let key = crypto::generate_master_key();
                    Self::store_master_key(&key)?;
                    Ok(key.to_vec())
                }
                Err(error) => Err(error),
            }
        }

        pub fn read_master_key() -> Result<Vec<u8>> {
            unsafe {
                let dict = base_query()?;
                CFDictionarySetValue(dict.0, kSecReturnData, kCFBooleanTrue);
                CFDictionarySetValue(dict.0, kSecMatchLimit, kSecMatchLimitOne);

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

        fn store_master_key(key: &[u8; crypto::MASTER_KEY_LEN]) -> Result<()> {
            unsafe {
                let dict = base_query()?;
                let data = cf_data(key)?;
                CFDictionarySetValue(dict.0, kSecValueData, data.0);

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

    unsafe fn ns_string(value: &str) -> Result<OwnedObjc> {
        let string: *mut Object = msg_send![class!(NSString), alloc];
        let string: *mut Object = msg_send![
            string,
            initWithBytes:value.as_ptr()
            length:value.len()
            encoding:NS_UTF8_STRING_ENCODING
        ];
        if string.is_null() {
            bail!("failed to create NSString");
        }
        Ok(OwnedObjc(string))
    }

    fn authenticate(policy: AccessPolicy, reason: &str) -> Result<Option<String>> {
        unsafe {
            let context: *mut Object = msg_send![class!(LAContext), new];
            if context.is_null() {
                bail!("failed to create LocalAuthentication context");
            }
            let context = OwnedObjc(context);
            let reason = ns_string(reason)?;
            let policy_code = match policy {
                AccessPolicy::UserPresence => LA_POLICY_DEVICE_OWNER_AUTHENTICATION,
                AccessPolicy::BiometryCurrentSet => {
                    LA_POLICY_DEVICE_OWNER_AUTHENTICATION_WITH_BIOMETRICS
                }
            };

            let mut error: *mut Object = ptr::null_mut();
            let can_evaluate: BOOL =
                msg_send![context.0, canEvaluatePolicy:policy_code error:&mut error];
            if can_evaluate != YES {
                bail!(
                    "LocalAuthentication cannot evaluate {}; make sure Touch ID or device owner authentication is enabled",
                    policy.as_str()
                );
            }

            let (tx, rx) = mpsc::channel();
            let reply = ConcreteBlock::new(move |success: BOOL, error: *mut Object| {
                let _ = tx.send((success == YES, !error.is_null()));
            })
            .copy();

            let _: () = msg_send![
                context.0,
                evaluatePolicy:policy_code
                localizedReason:reason.0
                reply:&*reply
            ];

            let (success, had_error) = rx
                .recv()
                .context("failed to receive LocalAuthentication result")?;
            if !success {
                if had_error {
                    bail!("LocalAuthentication was not approved");
                }
                bail!("LocalAuthentication failed");
            }

            let state: *mut Object = msg_send![context.0, evaluatedPolicyDomainState];
            Ok(ns_data_base64(state))
        }
    }

    unsafe fn ns_data_base64(data: *mut Object) -> Option<String> {
        if data.is_null() {
            return None;
        }
        let len: usize = msg_send![data, length];
        let bytes: *const u8 = msg_send![data, bytes];
        if bytes.is_null() || len == 0 {
            return None;
        }
        let bytes = std::slice::from_raw_parts(bytes, len);
        Some(BASE64_STANDARD.encode(bytes))
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

    struct OwnedObjc(*mut Object);

    impl Drop for OwnedObjc {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _: () = msg_send![self.0, release];
                }
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
    pub fn authenticate(_policy: AccessPolicy, _reason: &str) -> anyhow::Result<Option<String>> {
        anyhow::bail!("Nerdovault v1 requires macOS LocalAuthentication")
    }

    pub fn load_or_create_master_key(_policy: AccessPolicy) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("Nerdovault v1 requires macOS Keychain")
    }

    pub fn read_master_key() -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("Nerdovault v1 requires macOS Keychain")
    }

    pub fn master_key_exists() -> anyhow::Result<bool> {
        Ok(false)
    }
}
