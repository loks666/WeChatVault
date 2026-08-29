use std::ffi::OsString;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

pub struct ProcessHandle {
    pub pid: u32,
    pub handle: HANDLE,
}

impl ProcessHandle {
    pub fn open(pid: u32) -> Option<Self> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                None
            } else {
                Some(Self { pid, handle })
            }
        }
    }

    pub fn read_memory(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }
        let mut buf = vec![0u8; len];
        let mut bytes_read = 0usize;
        unsafe {
            let res = ReadProcessMemory(
                self.handle,
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                len,
                &mut bytes_read,
            );
            if res != 0 && bytes_read > 0 {
                buf.truncate(bytes_read);
                Some(buf)
            } else {
                None
            }
        }
    }

    pub fn query_memory_regions(&self) -> Vec<(usize, usize)> {
        let mut regions = Vec::new();
        let mut addr = 0usize;
        let mbi_size = size_of::<MEMORY_BASIC_INFORMATION>();

        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            while VirtualQueryEx(self.handle, addr as *const _, &mut mbi, mbi_size) != 0 {
                let state = mbi.State;
                let protect = mbi.Protect;
                let region_size = mbi.RegionSize;
                let base_addr = mbi.BaseAddress as usize;

                let is_readable = (state & MEM_COMMIT != 0)
                    && (protect & (PAGE_NOACCESS | PAGE_GUARD) == 0)
                    && region_size > 0
                    && region_size < 0x1000_0000;

                if is_readable {
                    regions.push((base_addr, region_size));
                }

                addr = base_addr + region_size;
                if addr >= 0x7FFF_FFFF_FFFF {
                    break;
                }
            }
        }

        regions
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

pub fn find_weixin_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return pids;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let null_pos = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let exe_name = OsString::from_wide(&entry.szExeFile[..null_pos])
                    .to_string_lossy()
                    .to_lowercase();

                if exe_name == "weixin.exe" {
                    pids.push(entry.th32ProcessID);
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }
    pids
}

pub fn find_weixin_module(pid: u32) -> Option<(usize, usize, String)> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let null_pos = entry
                    .szModule
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szModule.len());
                let mod_name = OsString::from_wide(&entry.szModule[..null_pos])
                    .to_string_lossy()
                    .to_lowercase();

                if mod_name == "weixin.dll" {
                    let path_null = entry
                        .szExePath
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExePath.len());
                    let path = OsString::from_wide(&entry.szExePath[..path_null])
                        .to_string_lossy()
                        .to_string();

                    let base = entry.modBaseAddr as usize;
                    let size = entry.modBaseSize as usize;
                    CloseHandle(snapshot);
                    return Some((base, size, path));
                }

                if Module32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }
    None
}
