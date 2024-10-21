#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::ffi::c_void;
use std::os::windows::raw::HANDLE;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct winpty_error_s {
    _unused: [u8; 0],
}

pub type winpty_error_t = winpty_error_s;
pub type winpty_error_ptr_t = *mut winpty_error_t;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct winpty_config_s {
    _unused: [u8; 0],
}
pub type winpty_config_t = winpty_config_s;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct winpty_s {
    _unused: [u8; 0],
}
pub type winpty_t = winpty_s;

impl winpty_t {
    pub fn new() -> Self {
        Self { _unused: [] }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct winpty_spawn_config_s {
    _unused: [u8; 0],
}
pub type winpty_spawn_config_t = winpty_spawn_config_s;

extern "C" {

    pub fn winpty_error_code(err: *mut winpty_error_ptr_t) -> u32;
    pub fn winpty_error_msg(err: *mut winpty_error_ptr_t) -> *const u16;
    pub fn winpty_error_free(err: *mut winpty_error_ptr_t);

    pub fn winpty_config_new(flags: u64, err: *mut winpty_error_ptr_t) -> *mut winpty_config_t;
    pub fn winpty_config_free(cfg: *mut winpty_config_t);
    pub fn winpty_config_set_initial_size(cfg: *mut winpty_config_t, cols: i32, rows: i32);
    pub fn winpty_config_set_mouse_mode(cfg: *mut winpty_config_t, mouse_mode: i32);
    pub fn winpty_config_set_agent_timeout(cfg: *mut winpty_config_t, timeout: u32);

    pub fn winpty_open(cfg: *const winpty_config_t, err: *mut winpty_error_ptr_t) -> *mut winpty_t;
    pub fn winpty_agent_process(wp: *mut winpty_t) -> *const c_void;

    pub fn winpty_conin_name(wp: *mut winpty_t) -> *const u16;
    pub fn winpty_conout_name(wp: *mut winpty_t) -> *const u16;
    pub fn winpty_conerr_name(wp: *mut winpty_t) -> *const u16;

    pub fn winpty_spawn_config_new(
        spawn_flags: u64,
        appname: *const u16,
        cmdline: *const u16,
        cwd: *const u16,
        env: *const u16,
        err: *mut winpty_error_ptr_t,
    ) -> *mut winpty_spawn_config_t;

    pub fn winpty_spawn_config_free(cfg: *mut winpty_spawn_config_t);
    pub fn winpty_spawn(
        wp: *mut winpty_t,
        cfg: *const winpty_spawn_config_t,
        process_handle: *mut HANDLE,
        thread_handle: *mut HANDLE,
        create_process_error: *mut u32,
        err: *mut winpty_error_ptr_t,
    ) -> bool;

    pub fn winpty_set_size(
        wp: *mut winpty_t,
        cols: i32,
        rows: i32,
        err: *mut winpty_error_ptr_t,
    ) -> bool;
    pub fn winpty_free(wp: *mut winpty_t);
}
