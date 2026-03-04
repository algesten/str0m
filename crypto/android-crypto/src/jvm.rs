use jni::JavaVM;
use once_cell::sync::OnceCell;

/// Global JVM reference for JNI calls.
static JVM: OnceCell<JavaVM> = OnceCell::new();

/// Initialize the Android crypto provider with the JVM.
///
/// This must be called before using any crypto operations, typically in
/// `JNI_OnLoad` or during application initialization.
///
/// # Panics
///
/// Panics if called more than once.
///
/// # Example
///
/// ```ignore
/// #[no_mangle]
/// pub extern "C" fn JNI_OnLoad(vm: jni::JavaVM, _reserved: *mut std::ffi::c_void) -> jni::sys::jint {
///     str0m_android_crypto::init_jvm(vm);
///     jni::sys::JNI_VERSION_1_6
/// }
/// ```
#[cfg(not(test))]
pub fn init_jvm(vm: JavaVM) {
    JVM.set(vm)
        .expect("JVM already initialized for android-crypto");
}

/// Get the global JVM reference.
///
/// When running from a rust binary (such as cargo ndk-test) this will
/// create a JVM on demand. For applications, they should instead call init_jvm.
pub(crate) fn get_jvm() -> &'static JavaVM {
    JVM.get_or_init(create_test_jvm)
}

/// Create a JVM for testing by dynamically loading the Android runtime.
///
/// On Android, a native test binary has no JVM. We bootstrap one by:
/// 1. Loading `libnativehelper.so` and calling `JniInvocationCreate` + `JniInvocationInit`
///    to load the ART runtime (`libart.so`).
/// 2. Calling `JNI_CreateJavaVM` to create the VM.
fn create_test_jvm() -> JavaVM {
    use std::ffi::c_void;
    use std::ptr;

    extern "C" {
        fn dlopen(filename: *const std::ffi::c_char, flag: std::ffi::c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const std::ffi::c_char) -> *mut c_void;
    }

    const RTLD_NOW: std::ffi::c_int = 2;

    // Function pointer types for the JNI invocation and VM creation APIs.
    type JniInvocationCreateFn = unsafe extern "C" fn() -> *mut c_void;
    type JniInvocationInitFn =
        unsafe extern "C" fn(instance: *mut c_void, library: *const std::ffi::c_char) -> bool;
    type CreateJavaVmFn = unsafe extern "system" fn(
        pvm: *mut *mut jni::sys::JavaVM,
        penv: *mut *mut c_void,
        args: *mut c_void,
    ) -> jni::sys::jint;

    /// Load a symbol from a shared library handle, panicking with a message on failure.
    unsafe fn load_sym(lib: *mut c_void, name: &[u8]) -> *mut c_void {
        let sym = unsafe { dlsym(lib, name.as_ptr().cast()) };
        assert!(
            !sym.is_null(),
            "Symbol not found: {}",
            std::str::from_utf8(&name[..name.len() - 1]).unwrap_or("<invalid>")
        );
        sym
    }

    // Load libnativehelper.so which provides the JniInvocation API and JNI_CreateJavaVM.
    // Safety: passing a valid null-terminated string to dlopen.
    let helper_lib = unsafe { dlopen(b"libnativehelper.so\0".as_ptr().cast(), RTLD_NOW) };
    assert!(
        !helper_lib.is_null(),
        "Failed to dlopen libnativehelper.so — is this running on an Android device?"
    );

    // Bootstrap the ART runtime via the JniInvocation API.
    // Safety: the symbols have the documented signatures from libnativehelper.
    unsafe {
        let invocation_create: JniInvocationCreateFn =
            std::mem::transmute(load_sym(helper_lib, b"JniInvocationCreate\0"));
        let invocation_init: JniInvocationInitFn =
            std::mem::transmute(load_sym(helper_lib, b"JniInvocationInit\0"));

        let instance = invocation_create();
        assert!(!instance.is_null(), "JniInvocationCreate returned null");

        // Passing null for library selects the default runtime (libart.so).
        let ok = invocation_init(instance, ptr::null());
        assert!(ok, "JniInvocationInit failed — could not load ART runtime");
    }

    // Now JNI_CreateJavaVM is available.
    // Safety: load_sym returns a valid pointer to JNI_CreateJavaVM.
    let create_jvm: CreateJavaVmFn =
        unsafe { std::mem::transmute(load_sym(helper_lib, b"JNI_CreateJavaVM\0")) };

    let mut vm: *mut jni::sys::JavaVM = ptr::null_mut();
    let mut env: *mut c_void = ptr::null_mut();
    let mut args = jni::sys::JavaVMInitArgs {
        version: jni::sys::JNI_VERSION_1_6,
        nOptions: 0,
        options: ptr::null_mut(),
        ignoreUnrecognized: jni::sys::JNI_TRUE,
    };

    // Safety: calling JNI_CreateJavaVM with valid pointers.
    let rc = unsafe {
        create_jvm(
            &mut vm,
            &mut env,
            (&mut args as *mut jni::sys::JavaVMInitArgs).cast(),
        )
    };
    assert_eq!(
        rc,
        jni::sys::JNI_OK,
        "JNI_CreateJavaVM failed with code: {rc}"
    );

    // Safety: vm is a valid pointer returned by JNI_CreateJavaVM.
    unsafe { JavaVM::from_raw(vm).expect("Failed to wrap raw JavaVM pointer") }
}
