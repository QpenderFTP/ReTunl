//! Program icons for the app picker and the activity list (exe → PNG data URL).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use windows_sys::Win32::Graphics::Gdi::{
    CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits, GetObjectW, BITMAP, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
    DIB_RGB_COLORS,
};
use windows_sys::Win32::UI::Shell::ExtractIconExW;
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};

use crate::sys::wide;

pub fn exe_icon_data_url(path: &str) -> Option<String> {
    let png = exe_icon_png(path)?;
    Some(format!("data:image/png;base64,{}", STANDARD.encode(png)))
}

fn exe_icon_png(path: &str) -> Option<Vec<u8>> {
    let wpath = wide(path);
    unsafe {
        let mut large: HICON = std::ptr::null_mut();
        let n = ExtractIconExW(wpath.as_ptr(), 0, &mut large, std::ptr::null_mut(), 1);
        if n == 0 || large.is_null() {
            return None;
        }
        let png = icon_to_png(large);
        DestroyIcon(large);
        png
    }
}

unsafe fn icon_to_png(icon: HICON) -> Option<Vec<u8>> {
    let mut info: ICONINFO = std::mem::zeroed();
    if GetIconInfo(icon, &mut info) == 0 {
        return None;
    }
    let color = info.hbmColor;
    let mask = info.hbmMask;
    let result = read_pixels(color, mask);
    if !color.is_null() {
        DeleteObject(color as _);
    }
    if !mask.is_null() {
        DeleteObject(mask as _);
    }
    let (w, h, rgba) = result?;
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc.write_header().ok()?;
        writer.write_image_data(&rgba).ok()?;
    }
    Some(out)
}

unsafe fn read_pixels(
    color: windows_sys::Win32::Graphics::Gdi::HBITMAP,
    mask: windows_sys::Win32::Graphics::Gdi::HBITMAP,
) -> Option<(u32, u32, Vec<u8>)> {
    if color.is_null() {
        return None;
    }
    let mut bm: BITMAP = std::mem::zeroed();
    if GetObjectW(color as _, std::mem::size_of::<BITMAP>() as i32, &mut bm as *mut _ as *mut _) == 0 {
        return None;
    }
    let (w, h) = (bm.bmWidth, bm.bmHeight);
    if w <= 0 || h <= 0 || w > 256 || h > 256 {
        return None;
    }
    let mut bmi: BITMAPINFO = std::mem::zeroed();
    bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
    bmi.bmiHeader.biWidth = w;
    bmi.bmiHeader.biHeight = -h; // top-down
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    let size = (w * h * 4) as usize;
    let mut buf = vec![0u8; size];
    let dc = CreateCompatibleDC(std::ptr::null_mut());
    let lines = GetDIBits(dc, color, 0, h as u32, buf.as_mut_ptr() as *mut _, &mut bmi, DIB_RGB_COLORS);
    // old icons have no alpha channel: take transparency from the mask
    if lines != 0 && !buf.chunks(4).any(|p| p[3] != 0) && !mask.is_null() {
        let mut mbuf = vec![0u8; size];
        let mut mbmi = bmi;
        GetDIBits(dc, mask, 0, h as u32, mbuf.as_mut_ptr() as *mut _, &mut mbmi, DIB_RGB_COLORS);
        for (p, m) in buf.chunks_mut(4).zip(mbuf.chunks(4)) {
            p[3] = if m[0] == 0 { 255 } else { 0 };
        }
    }
    DeleteDC(dc);
    if lines == 0 {
        return None;
    }
    for p in buf.chunks_mut(4) {
        p.swap(0, 2); // BGRA → RGBA
    }
    Some((w as u32, h as u32, buf))
}
