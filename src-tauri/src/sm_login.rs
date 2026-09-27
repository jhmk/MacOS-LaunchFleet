//! Wrapper around `SMLoginItemSetEnabled` from ServiceManagement.framework.
//!
//! Deprecated since macOS 13, but still the only programmatic way to disable
//! app-bundled login items (`Contents/Library/LoginItems/`) without sending the
//! user to System Settings.
//!
//! Because it is resolved with `dlsym` rather than linked, Apple removing it
//! would surface as a *runtime* failure, not a build error — hence the explicit
//! `Err` path and the caller's System Settings fallback. The long-term fix is
//! `SMAppService.loginItem(identifier:)`, which requires an Objective-C bridge.

use core_foundation::base::TCFType;
use core_foundation::string::{CFString, CFStringRef};
use std::os::raw::c_char;
use std::sync::OnceLock;

type SMLoginItemSetEnabledFn = unsafe extern "C" fn(CFStringRef, bool) -> bool;

static FRAMEWORK_PATH: &[u8] =
    b"/System/Library/Frameworks/ServiceManagement.framework/ServiceManagement\0";
static SYMBOL_NAME: &[u8] = b"SMLoginItemSetEnabled\0";

/// `static mut` + `Once` was the previous approach; reading it was UB-adjacent
/// and becomes a hard error under edition 2024. `OnceLock` gives the same
/// one-shot initialisation with a safe API.
static FN_PTR: OnceLock<Option<SMLoginItemSetEnabledFn>> = OnceLock::new();

fn load() -> Option<SMLoginItemSetEnabledFn> {
    *FN_PTR.get_or_init(|| unsafe {
        let lib = libc::dlopen(FRAMEWORK_PATH.as_ptr() as *const c_char, libc::RTLD_NOW);
        if lib.is_null() {
            return None;
        }
        let sym = libc::dlsym(lib, SYMBOL_NAME.as_ptr() as *const c_char);
        if sym.is_null() {
            return None;
        }
        Some(std::mem::transmute::<
            *mut libc::c_void,
            SMLoginItemSetEnabledFn,
        >(sym))
    })
}

/// Enable or disable a login item registered via the legacy
/// `SMLoginItemSetEnabled` API. `Ok(false)` means the framework reported
/// failure (item not registered for this user); `Err` means the symbol is
/// unavailable on this OS version.
pub fn set_login_item_enabled(bundle_id: &str, enabled: bool) -> Result<bool, String> {
    let func = load().ok_or_else(|| {
        "SMLoginItemSetEnabled is unavailable on this version of macOS".to_string()
    })?;

    let cf_id = CFString::new(bundle_id);
    let result = unsafe { func(cf_id.as_concrete_TypeRef(), enabled) };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_resolution_is_cached_and_consistent() {
        let a = load().is_some();
        let b = load().is_some();
        assert_eq!(a, b);
    }

    #[test]
    fn unknown_bundle_id_does_not_panic() {
        if load().is_some() {
            let r = set_login_item_enabled("com.launchfleet.definitely.not.real", false);
            assert!(r.is_ok(), "should report failure, not panic");
        }
    }
}
