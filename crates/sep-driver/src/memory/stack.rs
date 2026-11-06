//! Scoped, protected stacks for reviewed synchronous crypto. Callers keep input
//! secrets in protected allocations and return only public/intentionally revealed
//! output. This covers stack storage, not secret heap allocations or registers.
use std::cell::Cell;
use std::io;
use std::mem::MaybeUninit;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::ptr::NonNull;
use zeroize::Zeroize;

const STACK_SIZE: usize = 512 * 1024;
thread_local! { static ON_PROTECTED_STACK: Cell<bool> = const { Cell::new(false) }; }

/// Runs a bounded synchronous computation on a temporary locked, dump-excluded,
/// non-inherited stack. Guard pages surround it. The caller joins the worker,
/// then wipes/unmaps its entire usable stack before returning or resuming panic.
/// Setup failure never executes the callback on an ordinary stack. Nested calls
/// reuse the current protected stack rather than allocating another lock budget.
///
/// This is not an authorization grant. F: Send prevents transferring thread-affine
/// guards/state. Avoid fork/exec, returning secret copies, allocating unwiped
/// secret heap storage, or formatting private values into panic/error messages.
pub fn with_secret_stack<F, T>(operation: F) -> io::Result<T>
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    if ON_PROTECTED_STACK.with(Cell::get) {
        return Ok(operation());
    }
    let stack = Stack::new()?;
    let outcome = execute(&stack, operation)?;
    // pthread_join completed, including TLS destructors. Nothing may access the
    // caller-owned stack now; erase it before exposing the outcome to the caller.
    drop(stack);
    match outcome {
        Ok(value) => Ok(value),
        Err(payload) => resume_unwind(payload),
    }
}

struct Stack {
    mapping: NonNull<u8>,
    usable: NonNull<u8>,
    size: usize,
    total: usize,
}
impl Stack {
    fn new() -> io::Result<Self> {
        // SAFETY: sysconf takes a constant selector, no caller pointers.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0 {
            return Err(io::Error::other("cannot determine crypto stack page size"));
        }
        let page = page as usize;
        let size = STACK_SIZE.div_ceil(page) * page;
        let total = size + 2 * page;
        // SAFETY: kernel-selected private anonymous mapping. PROT_NONE guards
        // remain inaccessible; only the interior is made writable below.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let Some(mapping) = NonNull::new(raw.cast::<u8>()) else {
            // SAFETY: a successful mapping at zero still needs complete cleanup.
            unsafe {
                libc::munmap(raw, total);
            }
            return Err(io::Error::other("null crypto stack mapping"));
        };
        // SAFETY: page points into the live mapping, leaving two whole guards.
        let usable = unsafe { NonNull::new_unchecked(mapping.as_ptr().add(page)) };
        // SAFETY: exactly the aligned interior of this mapping becomes writable.
        if unsafe {
            libc::mprotect(
                usable.as_ptr().cast(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            // SAFETY: no object/worker or secret has entered this mapping.
            unsafe {
                libc::munmap(raw, total);
            }
            return Err(error);
        }
        let stack = Self {
            mapping,
            usable,
            size,
            total,
        };
        // SAFETY: the entire live writable stack is locked before worker creation.
        if unsafe { libc::mlock(stack.usable.as_ptr().cast(), size) } != 0 {
            return Err(io::Error::last_os_error());
        }
        for advice in [libc::MADV_DONTDUMP, libc::MADV_DONTFORK] {
            // SAFETY: advice covers the complete owned mapping including guards.
            if unsafe { libc::madvise(raw, total, advice) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(stack)
    }
    fn wipe(&mut self) {
        // SAFETY: only called before a worker starts or after joining it. The
        // interior remains exclusively owned/writable; guards are never touched.
        unsafe { std::slice::from_raw_parts_mut(self.usable.as_ptr(), self.size) }.zeroize();
    }
}
impl Drop for Stack {
    fn drop(&mut self) {
        self.wipe();
        // SAFETY: no worker remains; unlock only the interior and unmap all pages.
        unsafe {
            libc::munlock(self.usable.as_ptr().cast(), self.size);
            libc::munmap(self.mapping.as_ptr().cast(), self.total);
        }
    }
}
struct Attributes(libc::pthread_attr_t);
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: this wrapper is constructed only after successful attr_init.
        unsafe {
            libc::pthread_attr_destroy(&mut self.0);
        }
    }
}
struct Task<F, T> {
    operation: Option<F>,
    outcome: Option<std::thread::Result<T>>,
}
extern "C" fn entry<F, T>(raw: *mut libc::c_void) -> *mut libc::c_void
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    // SAFETY: execute transfers this live, uniquely borrowed Box to this exact
    // worker. The parent cannot read/drop it until pthread_join synchronizes.
    let task = unsafe { &mut *raw.cast::<Task<F, T>>() };
    ON_PROTECTED_STACK.with(|flag| flag.set(true));
    let Some(operation) = task.operation.take() else {
        std::process::abort()
    };
    // No Rust unwind may cross the C ABI boundary. The payload is resumed only
    // on the caller after joining and wiping/unmapping this worker stack.
    task.outcome = Some(catch_unwind(AssertUnwindSafe(operation)));
    ON_PROTECTED_STACK.with(|flag| flag.set(false));
    std::ptr::null_mut()
}
fn execute<F, T>(stack: &Stack, operation: F) -> io::Result<std::thread::Result<T>>
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    let mut attributes = MaybeUninit::<libc::pthread_attr_t>::uninit();
    // SAFETY: attr_init initializes the otherwise unread uninitialized object.
    let status = unsafe { libc::pthread_attr_init(attributes.as_mut_ptr()) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    // SAFETY: initialization succeeded above; Attributes owns its destruction.
    let mut attributes = Attributes(unsafe { attributes.assume_init() });
    // SAFETY: this caller-owned aligned stack remains live through join. The
    // interior meets PTHREAD_STACK_MIN and manually supplied guards surround it.
    let status = unsafe {
        libc::pthread_attr_setstack(&mut attributes.0, stack.usable.as_ptr().cast(), stack.size)
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    let task = Box::into_raw(Box::new(Task {
        operation: Some(operation),
        outcome: None,
    }));
    let mut thread = MaybeUninit::<libc::pthread_t>::uninit();
    // SAFETY: F/T are Send and may borrow only for this joined scope. The Box and
    // stack remain live; entry catches unwinds and writes only its private task.
    let status = unsafe {
        libc::pthread_create(
            thread.as_mut_ptr(),
            &attributes.0,
            entry::<F, T>,
            task.cast(),
        )
    };
    if status != 0 {
        // SAFETY: failed pthread_create never started a worker; regain ownership.
        drop(unsafe { Box::from_raw(task) });
        return Err(io::Error::from_raw_os_error(status));
    }
    // SAFETY: create initialized the sole join handle. No other code can detach
    // or join this worker, and joining precedes every read/drop of its storage.
    let status = unsafe { libc::pthread_join(thread.assume_init(), std::ptr::null_mut()) };
    if status != 0 {
        // Returning would permit dropping a potentially live stack and borrowed
        // callback: abort rather than risking use-after-free or secret fallback.
        std::process::abort();
    }
    // SAFETY: join establishes completion and visibility; sole Box ownership
    // returns to this caller. entry has stopped using all of these fields.
    let mut task = unsafe { Box::from_raw(task) };
    Ok(task.outcome.take().unwrap_or_else(|| std::process::abort()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn mapping(address: usize) -> String {
        let smaps = std::fs::read_to_string("/proc/self/smaps")
            .unwrap_or_else(|error| panic!("smaps: {error}"));
        let mut current = String::new();
        let mut selected = false;
        for line in smaps.lines() {
            if let Some(range) = line
                .split_whitespace()
                .next()
                .filter(|value| value.contains('-'))
            {
                if let Some((start, end)) = range.split_once('-').and_then(|(a, b)| {
                    Some((
                        usize::from_str_radix(a, 16).ok()?,
                        usize::from_str_radix(b, 16).ok()?,
                    ))
                }) {
                    if selected {
                        break;
                    }
                    selected = (start..end).contains(&address);
                }
            }
            if selected {
                current.push_str(line);
                current.push('\n');
            }
        }
        current
    }
    #[test]
    fn worker_stack_is_locked_guarded_and_nested_calls_reuse_it() {
        let stack = Stack::new().unwrap_or_else(|error| panic!("stack: {error}"));
        for address in [
            stack.mapping.as_ptr() as usize,
            stack.usable.as_ptr() as usize + stack.size,
        ] {
            assert!(
                mapping(address)
                    .lines()
                    .next()
                    .is_some_and(|line| line.contains("---p"))
            );
        }
        let parent = std::thread::current().id();
        let result = execute(&stack, || {
            let probe = [0xabu8; 32];
            std::hint::black_box(&probe);
            let section = mapping(probe.as_ptr() as usize);
            let flags = section
                .lines()
                .find(|line| line.starts_with("VmFlags:"))
                .unwrap_or_else(|| panic!("stack flags missing"));
            for flag in ["lo", "dd", "dc"] {
                assert!(flags.split_whitespace().any(|value| value == flag));
            }
            assert_ne!(std::thread::current().id(), parent);
            let worker = std::thread::current().id();
            let nested = with_secret_stack(|| std::thread::current().id())
                .unwrap_or_else(|error| panic!("nested: {error}"));
            assert_eq!(nested, worker);
            nested
        })
        .unwrap_or_else(|error| panic!("execute: {error}"))
        .unwrap_or_else(|_| panic!("worker panic"));
        assert_ne!(result, parent);
    }
    #[test]
    fn success_and_unwind_stacks_are_wiped_after_join() {
        for panic in [false, true] {
            let mut stack = Stack::new().unwrap_or_else(|error| panic!("stack: {error}"));
            let ran = AtomicBool::new(false);
            let result = execute(&stack, || {
                let mut synthetic = [0x51u8; 4096];
                std::hint::black_box(&mut synthetic);
                ran.store(true, Ordering::Release);
                if panic {
                    panic!("synthetic crypto panic");
                }
                17
            })
            .unwrap_or_else(|error| panic!("execute: {error}"));
            assert!(ran.load(Ordering::Acquire));
            assert_eq!(result.is_err(), panic);
            stack.wipe();
            // SAFETY: the worker has joined; this owned mapping is still live.
            let bytes = unsafe { std::slice::from_raw_parts(stack.usable.as_ptr(), stack.size) };
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
        assert!(
            catch_unwind(|| with_secret_stack(|| panic!("synthetic propagated panic"))).is_err()
        );
        assert_eq!(
            with_secret_stack(|| 7).unwrap_or_else(|error| panic!("fresh stack: {error}")),
            7
        );
    }
}
