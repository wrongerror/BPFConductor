### Advanced eBPF Programming with Rust and Aya: Challenges and Solutions

## Introduction

In the previous article, "Building eBPF Programs from Scratch with Rust and Aya," we introduced how to start from
scratch to write eBPF programs using Rust and the Aya library. That article aimed to help readers grasp the basic eBPF
programming techniques and understand how to set up the development environment.

However, as the complexity of the projects increases, developers will encounter more advanced challenges and issues. In
this article, we will delve into some common problems encountered in writing complex eBPF programs and share specific
methods and techniques to solve these problems. We hope that this article will help developers better understand and
master advanced eBPF programming.

## Common Challenges in Advanced eBPF Programming

### Handling Complex Data Structures

- Only use enum variants that do not carry any data. Using enum variants with data will cause the eBPF verifier to fail.
- Avoid using structures with large fields directly in eBPF programs.
- For structures with large fields, separate attribute fields and data fields (such as messages). If not separated, BPF
  will perform a lot of size arithmetic, so the appropriate approach is to place attribute fields in a sub-structure (
  such as `attr` or `inner`).

### Performance Optimization

- Different types of eBPF programs have different overheads. In general, the order of preference under the premise of
  meeting functional requirements is: `tracepoint > fentry/fexit > kprobe/kretprobe`.
- Do not assign heavy computational analysis tasks to eBPF programs. eBPF programs in kernel space should primarily
  handle filtering, logging events, and event-related data, while other tasks are more suitable for user-space
  programs in most cases.
- The `#[repr(C, packed)]` attribute can simplify memory alignment issues, but it has potential performance risks, so
  use it with caution.
- Prefer Perf Event Array over Hash Map for transferring event data from kernel space to user space.
- If the kernel version meets the requirements, eBPF ring buffer is preferred over perf event array.

### Memory Management and Safety

#### Memory Layout

To ensure correctness and performance when transferring data between kernel and user space, eBPF programs have strict
requirements on the memory layout of structures. Using the `#[repr(C)]` attribute ensures that the structure's memory
layout is consistent with that in C. However, for enum types, use `#[repr(u32)]` or `#[repr(u64)]` to ensure the type of
the enum is determined. Additionally, it is recommended to arrange fields with larger sizes before smaller ones. If
there are still memory layout issues, manual alignment may be necessary, such as modifying field types to avoid padding
inserted by the Rust compiler, which can cause the eBPF verifier to complain about accessing uninitialized memory.

For reading and writing large fields, use helper functions like `bpf_probe_read_kernel_buf` for writing. If reading is
required, use pointers. Do not read such fields into stack space, as it may cause stack overflow.

#### bpf loop

For loops, the number of iterations should be determined and not calculated at runtime. This is also a limitation of the
eBPF verifier, which ensures that the program will always complete execution.

#### Pointers

Be cautious when accessing pointers, as many issues during debugging are caused by pointer access.

- Do not directly dereference pointers in the kernel; use `bpf_probe_read_kernel` to access them.
- Some fields in kernel structures may be user-space pointers and should not be directly dereferenced.
  Use `bpf_probe_read_user` to access them.
    - To distinguish between kernel and user pointers, check the definitions of the functions and structures in the
      kernel header files. For example, socket-related definitions can be found
      in `/usr/src/linux-headers-5.15.0-43-generic/include/linux/socket.h`.
    - Note that fields marked with `__user` in kernel structures are kernel pointers themselves, but the content they
      point to is a user pointer.
- Be cautious when using helper functions like `bpf_probe_read_kernel`/`bpf_probe_read_user`. If the structure being
  read is too complex, such as `tcp_sock`, it may cause memory overflow in the eBPF program. In such cases, read
  specific fields of the structure instead of the entire structure.
- eBPF programs allow pointers to be stored in eBPF maps, which is useful for handling data read/write buffers. However,
  be mindful of the pointer's validity period.
- Pointer types can be flexibly converted. In the kernel, fields defined with the `union` keyword or structures defined
  in an inheritance-like manner can be safely converted, such as `sockaddr`, `sockaddr_in4`, and `sockaddr_in6`.
  However, be cautious of out-of-bounds issues.

## Debugging Techniques

Debugging eBPF programs is relatively limited. The following methods can be used in combination:

- Aya provides `aya-log` to help simplify logging in eBPF programs. However, avoid logging too frequently, as it may
  cause errors. Choose appropriate points for logging.
- If the eBPF program passes the verifier and runs normally, besides logging, you can also write a similar eBPF program
  using bpftrace and compare the results.
- In addition to eBPF-related documentation, the man pages, Linux kernel header files/source code, and the contents of
  the `/sys/kernel/tracing/` directory are good choices when other methods fail. The more familiar you are with the
  kernel, the better you can handle the issues you encounter.

## Conclusion

In this article, we explored advanced challenges in eBPF programming with Rust and Aya, including handling complex data
structures, performance optimization, memory management, and debugging techniques. We discussed how to manage large
fields in structures, the importance of memory layout, and the use of helper functions for safe memory access.
Additionally, we covered performance considerations, such as choosing the appropriate type of eBPF program and the use
of Perf Event Array and ring buffers for data transfer. Finally, we provided debugging tips and emphasized the
importance of understanding kernel internals for effective problem-solving. This comprehensive guide aims to help
developers master advanced eBPF programming techniques and overcome common challenges.