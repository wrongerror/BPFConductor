// helper functions

use core::{cell::UnsafeCell, marker::PhantomData};

use aya_ebpf::{
    bindings::{BPF_F_CURRENT_CPU, bpf_map_def, bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY},
    cty::{c_long, c_void},
    EbpfContext,
    helpers::{
        bpf_get_current_task, bpf_perf_event_output, bpf_probe_read_kernel, gen::bpf_probe_read,
    },
};

use crate::vmlinux::task_struct;

const NSEC_PER_SEC: u64 = 1_000_000_000;
const USER_HZ: u64 = 100;

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PinningType {
    None = 0,
    ByName = 1,
}

#[repr(transparent)]
pub struct MyPerfEventArray<T> {
    def: UnsafeCell<bpf_map_def>,
    _t: PhantomData<T>,
}

unsafe impl<T: Sync> Sync for MyPerfEventArray<T> {}

impl<T> MyPerfEventArray<T> {
    pub const fn new(flags: u32) -> MyPerfEventArray<T> {
        MyPerfEventArray::with_max_entries(0, flags)
    }

    pub const fn with_max_entries(max_entries: u32, flags: u32) -> MyPerfEventArray<T> {
        MyPerfEventArray {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                key_size: size_of::<u32>() as u32,
                value_size: size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
            _t: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> MyPerfEventArray<T> {
        MyPerfEventArray {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                key_size: size_of::<u32>() as u32,
                value_size: size_of::<u32>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
            _t: PhantomData,
        }
    }

    pub fn output<C: EbpfContext>(&self, ctx: &C, data: &T, flags: u32) {
        self.output_at_index(ctx, BPF_F_CURRENT_CPU as u32, data, flags)
    }

    pub fn output_at_index<C: EbpfContext>(&self, ctx: &C, index: u32, data: &T, flags: u32) {
        let flags = u64::from(flags) << 32 | u64::from(index);
        unsafe {
            bpf_perf_event_output(
                ctx.as_ptr(),
                self.def.get() as *mut _,
                flags,
                data as *const _ as *mut _,
                size_of::<T>() as u64,
            );
        }
    }

    pub fn output_with_size<C: EbpfContext>(&self, ctx: &C, data: &T, size: u64, flags: u32) {
        self.output_at_index_with_size(ctx, BPF_F_CURRENT_CPU as u32, data, size, flags)
    }

    pub fn output_at_index_with_size<C: EbpfContext>(
        &self,
        ctx: &C,
        index: u32,
        data: &T,
        size: u64,
        flags: u32,
    ) {
        let flags = u64::from(flags) << 32 | u64::from(index);
        unsafe {
            bpf_perf_event_output(
                ctx.as_ptr(),
                self.def.get() as *mut _,
                flags,
                data as *const _ as *mut _,
                size,
            );
        }
    }
}

#[inline]
pub unsafe fn bpf_probe_read_buf_with_size(
    dst: &mut [u8],
    size: usize,
    src: *const u8,
) -> Result<(), c_long> {
    let read_size = core::cmp::min(size, dst.len());
    let ret = bpf_probe_read(
        dst.as_mut_ptr() as *mut c_void,
        read_size as u32,
        src as *const c_void,
    );
    if ret == 0 {
        Ok(())
    } else {
        Err(ret)
    }
}

#[inline]
fn pl_nsec_to_clock_t(x: u64) -> u64 {
    x / (NSEC_PER_SEC / USER_HZ)
}

#[inline]
pub fn get_tgid_start_time() -> Result<u64, i32> {
    let task: *const task_struct = unsafe { bpf_get_current_task() as *const task_struct };
    if task.is_null() {
        return Err(1);
    }

    let group_leader: *const task_struct = unsafe {
        bpf_probe_read_kernel(&(*task).group_leader as *const _ as *const u64).map_err(|_| 1i32)?
            as *const task_struct
    };

    let start_boottime = unsafe {
        bpf_probe_read_kernel(&(*group_leader).start_boottime as *const u64).map_err(|_| 1i32)?
    };

    Ok(pl_nsec_to_clock_t(start_boottime))
}
