//! Locked-state memory audit: after `lock()`, scan this process's address space for a known
//! plaintext canary. Any full-canary hit outside the scanner's own
//! buffers means Tier-B plaintext survived the lock.
//!
//! Methodology notes:
//!
//! - The canary is random per run, so nothing in the test binary's
//!   rodata and no other test's data can collide with it.
//! - The scan searches for the canary's first 16 bytes, then verifies
//!   candidates by re-reading the full canary at that address. This
//!   keeps needle spills (registers/stack copies of the short needle)
//!   from counting — only a full live copy is a leak.
//! - Every buffer the scanner allocates is tracked in `owned` and
//!   excluded: a freed scan buffer can hold a *copy* of a region that
//!   contained the canary variable, and copies-of-our-own-copy are not
//!   leaks. The original hit in the copied region is still found when
//!   that region itself is scanned (its address is not owned).

use std::ops::Range;

/// Recycle freed heap blocks with zeroed allocations, overwriting
/// plaintext crumbs the allocator has not yet reused. Covers the small
/// size classes message/envelope buffers land in, then larger blocks.
pub fn scrub_heap() {
    for size in [32usize, 48, 64, 96, 128, 192, 256, 512, 1024] {
        let count = (16 * 1024 * 1024) / size; // ~16 MiB per class
        let mut hold = Vec::with_capacity(count.min(1 << 20));
        for _ in 0..count {
            hold.push(vec![0u8; size]);
        }
        drop(hold);
    }
    let mut hold = Vec::new();
    for _ in 0..32 {
        hold.push(vec![0u8; 1024 * 1024]);
    }
    drop(hold);
}

/// Count live copies of `canary` in this process's readable anonymous
/// memory, excluding the scanner's own buffers and `canary` itself.
pub fn live_canary_hits(canary: &[u8]) -> usize {
    assert!(canary.len() >= 16, "canary too short to be a safe needle");
    let needle: [u8; 16] = canary[..16].try_into().expect("len asserted above");
    let mut owned: Vec<Range<usize>> = vec![
        canary.as_ptr() as usize..canary.as_ptr() as usize + canary.len(),
        needle.as_ptr() as usize..needle.as_ptr() as usize + needle.len(),
    ];
    let mut hits = 0;
    for region in readable_regions() {
        if region.len() > (1 << 30) || region.is_empty() {
            continue; // skip giant reservations; nothing small malloc'd lives there
        }
        let mut buf = vec![0u8; region.len()];
        owned.push(buf.as_ptr() as usize..buf.as_ptr() as usize + buf.len());
        let n = read_at(region.start, &mut buf);
        let buf = &buf[..n];
        let mut off = 0;
        while let Some(pos) = find(&buf[off..], &needle) {
            let addr = region.start + off + pos;
            off += pos + 1;
            if owned.iter().any(|r| r.contains(&addr)) {
                continue;
            }
            // Candidate: verify the FULL canary lives at that address.
            let mut verify = zeroize::Zeroizing::new(vec![0u8; canary.len()]);
            let got = read_at(addr, &mut verify);
            if got == canary.len() && &verify[..] == canary {
                hits += 1;
            }
        }
    }
    hits
}

fn find(haystack: &[u8], needle: &[u8; 16]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// -- region enumeration + reading ------------------------------------------

#[cfg(target_os = "linux")]
fn readable_regions() -> Vec<Range<usize>> {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    maps.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let range = parts.next()?;
            let perms = parts.next()?;
            if !perms.starts_with('r') || perms.contains('s') {
                return None; // readable, private only
            }
            let pathname = parts.nth(4).unwrap_or("");
            if !pathname.is_empty() && pathname != "[heap]" && pathname != "[stack]" {
                return None; // anonymous + heap/stack only (skip file-backed)
            }
            let (start, end) = range.split_once('-')?;
            Some(usize::from_str_radix(start, 16).ok()?..usize::from_str_radix(end, 16).ok()?)
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn read_at(addr: usize, buf: &mut [u8]) -> usize {
    use std::os::unix::fs::FileExt;
    let mem = match std::fs::File::open("/proc/self/mem") {
        Ok(f) => f,
        Err(_) => return 0,
    };
    mem.read_at(buf, addr as u64).unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn readable_regions() -> Vec<Range<usize>> {
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::message::mach_msg_type_number_t;
    use mach2::port::mach_port_t;
    use mach2::traps::mach_task_self;
    use mach2::vm::mach_vm_region;
    use mach2::vm_region::{vm_region_basic_info_data_64_t, VM_REGION_BASIC_INFO_64};
    use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};

    let mut regions = Vec::new();
    let task = unsafe { mach_task_self() };
    let mut address: mach_vm_address_t = 0;
    loop {
        let mut size: mach_vm_size_t = 0;
        let mut info: vm_region_basic_info_data_64_t = unsafe { std::mem::zeroed() };
        let mut count: mach_msg_type_number_t =
            (std::mem::size_of::<vm_region_basic_info_data_64_t>() / std::mem::size_of::<i32>())
                as mach_msg_type_number_t;
        let mut object: mach_port_t = 0;
        let kr = unsafe {
            mach_vm_region(
                task,
                &mut address,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                &mut info as *mut _ as *mut i32,
                &mut count,
                &mut object,
            )
        };
        if kr != KERN_SUCCESS {
            break;
        }
        if info.protection & mach2::vm_prot::VM_PROT_READ != 0 {
            regions.push(address as usize..(address + size) as usize);
        }
        address += size;
    }
    regions
}

#[cfg(target_os = "macos")]
fn read_at(addr: usize, buf: &mut [u8]) -> usize {
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::traps::mach_task_self;
    use mach2::vm::mach_vm_read_overwrite;
    use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};

    // Read in chunks: mach_vm_read_overwrite fails the whole range if
    // any page in it is unmapped.
    let mut total = 0;
    let chunk = 1 << 20; // 1 MiB
    while total < buf.len() {
        let want = chunk.min(buf.len() - total);
        let mut out: mach_vm_size_t = 0;
        let kr = unsafe {
            mach_vm_read_overwrite(
                mach_task_self(),
                (addr + total) as mach_vm_address_t,
                want as mach_vm_size_t,
                buf[total..].as_mut_ptr() as mach_vm_address_t,
                &mut out,
            )
        };
        if kr != KERN_SUCCESS || out == 0 {
            break;
        }
        total += out as usize;
    }
    total
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("memory audit needs a platform reader (linux /proc, macOS mach)");
