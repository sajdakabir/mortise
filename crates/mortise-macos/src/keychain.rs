//! Keychain FFI.
//!
//! Every `unsafe` block in the project is in this file. Each one is annotated
//! with why it is sound.
//!
//! Core Foundation memory rules followed here:
//! - anything from a `*Create*` function is owned (+1) and must be released;
//!   `SecAccessControlCreateWithFlags` and `SecItemCopyMatching`'s out-param
//!   are the two cases
//! - `core-foundation`'s `CFString`/`CFData`/`CFDictionary` wrappers release on
//!   drop, so values built through them need no manual handling
//! - `extern "C"` constants are immortal and are only borrowed

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFRelease, CFTypeRef, kCFAllocatorDefault};
use core_foundation_sys::error::CFErrorRef;
use security_framework_sys::access_control::{
    SecAccessControlCreateWithFlags, kSecAccessControlUserPresence,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
};
use security_framework_sys::base::SecAccessControlRef;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword,
    kSecMatchLimit, kSecReturnAttributes, kSecReturnData, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

// Not re-exported by security-framework-sys, but exported by Security.framework.
// security-framework-sys exposes the kSecAttrAccessible* *values* but not the
// attribute key itself, so that is declared here too.
unsafe extern "C" {
    static kSecMatchLimitOne: core_foundation_sys::string::CFStringRef;
    static kSecUseOperationPrompt: core_foundation_sys::string::CFStringRef;
    static kSecAttrAccessible: core_foundation_sys::string::CFStringRef;
}

// OSStatus values from <Security/SecBase.h>.
const ERR_SEC_SUCCESS: i32 = 0;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
/// errSecMissingEntitlement. Raised when an unsigned binary tries to create an
/// access-controlled item.
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

/// How a stored secret is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// Readable whenever the Mac is unlocked, with no prompt.
    ///
    /// `ThisDeviceOnly`, so it never syncs to iCloud Keychain — a key that
    /// roams defeats the point of an account key bound to a device.
    DeviceUnlocked,

    /// Requires Touch ID or the device passcode on every read.
    ///
    /// Enforced by the keychain itself, not by us.
    UserPresence,
}

/// Store `secret`, replacing any existing value.
pub fn store(service: &str, account: &str, secret: &[u8], protection: Protection) -> Result<()> {
    // SecItemAdd fails with errSecDuplicateItem rather than overwriting, and
    // SecItemUpdate cannot change an access control, so replace wholesale.
    let _ = delete(service, account);

    let class = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
    let svc = CFString::new(service);
    let acct = CFString::new(account);
    let data = CFData::from_buffer(secret);

    let mut pairs: Vec<(CFString, CFType)> = vec![
        (key(unsafe { kSecClass }), class.as_CFType()),
        (key(unsafe { kSecAttrService }), svc.as_CFType()),
        (key(unsafe { kSecAttrAccount }), acct.as_CFType()),
        (key(unsafe { kSecValueData }), data.as_CFType()),
    ];

    // An access control and a bare accessibility attribute are mutually
    // exclusive; setting both makes SecItemAdd fail with errSecParam.
    let access = match protection {
        Protection::DeviceUnlocked => {
            let accessible = unsafe {
                CFString::wrap_under_get_rule(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
            };
            pairs.push((key(unsafe { kSecAttrAccessible }), accessible.as_CFType()));
            None
        }
        Protection::UserPresence => {
            let access = create_access_control()?;
            // SAFETY: `access` is a valid +1 SecAccessControlRef from
            // SecAccessControlCreateWithFlags; wrap_under_get_rule retains it,
            // and `access` itself is released by OwnedRef below.
            let cf = unsafe { CFType::wrap_under_get_rule(access.0 as CFTypeRef) };
            pairs.push((key(unsafe { kSecAttrAccessControl }), cf));
            Some(access)
        }
    };

    let query = CFDictionary::from_CFType_pairs(&pairs);

    // SAFETY: `query` is a valid CFDictionary for the duration of the call, and
    // a null result pointer is documented as "discard the added item".
    let status = unsafe { SecItemAdd(query.as_concrete_TypeRef(), core::ptr::null_mut()) };
    drop(access);

    match status {
        ERR_SEC_SUCCESS => Ok(()),
        ERR_SEC_DUPLICATE_ITEM => Ok(()),
        other => Err(os_error(other)),
    }
}

/// Read a stored secret.
///
/// `prompt` is shown in the Touch ID dialog for [`Protection::UserPresence`]
/// items and ignored otherwise. Returns `Ok(None)` when no such item exists,
/// which is a normal state rather than an error.
///
/// **Blocks** while the prompt is on screen, so call it off the UI thread.
pub fn load(service: &str, account: &str, prompt: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let class = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
    let limit = unsafe { CFString::wrap_under_get_rule(kSecMatchLimitOne) };

    let pairs: Vec<(CFString, CFType)> = vec![
        (key(unsafe { kSecClass }), class.as_CFType()),
        (
            key(unsafe { kSecAttrService }),
            CFString::new(service).as_CFType(),
        ),
        (
            key(unsafe { kSecAttrAccount }),
            CFString::new(account).as_CFType(),
        ),
        (key(unsafe { kSecMatchLimit }), limit.as_CFType()),
        (key(unsafe { kSecReturnData }), cf_true()),
        (
            key(unsafe { kSecUseOperationPrompt }),
            CFString::new(prompt).as_CFType(),
        ),
    ];
    let query = CFDictionary::from_CFType_pairs(&pairs);

    let mut result: CFTypeRef = core::ptr::null_mut();
    // SAFETY: `query` is valid for the call; `result` is a valid out-pointer
    // and is only read when the status is success.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };

    match status {
        ERR_SEC_SUCCESS if !result.is_null() => {
            // SAFETY: on success with kSecReturnData the out-param is a +1
            // CFDataRef. wrap_under_create_rule takes ownership, so it is
            // released when `data` drops.
            let data = unsafe { CFData::wrap_under_create_rule(result as _) };
            Ok(Some(Zeroizing::new(data.to_vec())))
        }
        ERR_SEC_SUCCESS => Ok(None),
        ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        other => Err(os_error(other)),
    }
}

/// Whether an item exists, without reading it.
///
/// Asks for attributes rather than data, so a [`Protection::UserPresence`] item
/// can be detected without raising a Touch ID prompt. The UI needs this to
/// decide whether to offer biometric unlock at all, and prompting just to
/// render a button would be obnoxious.
pub fn exists(service: &str, account: &str) -> Result<bool> {
    let class = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
    let limit = unsafe { CFString::wrap_under_get_rule(kSecMatchLimitOne) };

    let pairs: Vec<(CFString, CFType)> = vec![
        (key(unsafe { kSecClass }), class.as_CFType()),
        (
            key(unsafe { kSecAttrService }),
            CFString::new(service).as_CFType(),
        ),
        (
            key(unsafe { kSecAttrAccount }),
            CFString::new(account).as_CFType(),
        ),
        (key(unsafe { kSecMatchLimit }), limit.as_CFType()),
        (key(unsafe { kSecReturnAttributes }), cf_true()),
    ];
    let query = CFDictionary::from_CFType_pairs(&pairs);

    let mut result: CFTypeRef = core::ptr::null_mut();
    // SAFETY: as in `load`; attributes are returned +1 and released here.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    if !result.is_null() {
        // SAFETY: `result` is a +1 CFType from a successful copy.
        unsafe { CFRelease(result) };
    }

    match status {
        ERR_SEC_SUCCESS => Ok(true),
        ERR_SEC_ITEM_NOT_FOUND => Ok(false),
        // An access-controlled item that refuses a non-interactive read still
        // proves the item is there, which is all this asks.
        ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_AUTH_FAILED => Ok(true),
        other => Err(os_error(other)),
    }
}

/// Remove a stored secret. Succeeds if it was already absent.
pub fn delete(service: &str, account: &str) -> Result<()> {
    let class = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };

    let pairs: Vec<(CFString, CFType)> = vec![
        (key(unsafe { kSecClass }), class.as_CFType()),
        (
            key(unsafe { kSecAttrService }),
            CFString::new(service).as_CFType(),
        ),
        (
            key(unsafe { kSecAttrAccount }),
            CFString::new(account).as_CFType(),
        ),
    ];
    let query = CFDictionary::from_CFType_pairs(&pairs);

    // SAFETY: `query` is valid for the call.
    let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
    match status {
        ERR_SEC_SUCCESS | ERR_SEC_ITEM_NOT_FOUND => Ok(()),
        other => Err(os_error(other)),
    }
}

/// Owns a `SecAccessControlRef` so it is released even on an early return.
struct OwnedRef(SecAccessControlRef);

impl Drop for OwnedRef {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` came from a *Create* function, so we own one
            // reference and release exactly that one.
            unsafe { CFRelease(self.0 as CFTypeRef) };
        }
    }
}

fn create_access_control() -> Result<OwnedRef> {
    let mut err: CFErrorRef = core::ptr::null_mut();

    // SAFETY: the protection constant is an immortal CF string from the
    // framework, and `err` is a valid out-pointer. The returned ref is +1 and
    // is owned by OwnedRef.
    let access = unsafe {
        SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
            kSecAccessControlUserPresence,
            &mut err,
        )
    };

    if !err.is_null() {
        // SAFETY: a non-null CFErrorRef from a Create function is +1.
        unsafe { CFRelease(err as CFTypeRef) };
    }
    if access.is_null() {
        return Err(Error::NotAvailable);
    }
    Ok(OwnedRef(access))
}

/// Borrow an immortal framework constant as a `CFString` key.
fn key(raw: core_foundation_sys::string::CFStringRef) -> CFString {
    // SAFETY: framework constants are immortal; get-rule borrows without
    // taking ownership, so nothing is over-released.
    unsafe { CFString::wrap_under_get_rule(raw) }
}

fn cf_true() -> CFType {
    // SAFETY: kCFBooleanTrue is an immortal CF constant.
    unsafe { CFType::wrap_under_get_rule(core_foundation_sys::number::kCFBooleanTrue as CFTypeRef) }
}

fn os_error(status: i32) -> Error {
    match status {
        ERR_SEC_USER_CANCELED => Error::Cancelled,
        ERR_SEC_AUTH_FAILED => Error::AuthFailed,
        ERR_SEC_MISSING_ENTITLEMENT => Error::RequiresSignedApp,
        ERR_SEC_NOT_AVAILABLE | ERR_SEC_INTERACTION_NOT_ALLOWED => Error::NotAvailable,
        other => Error::Os(other),
    }
}
