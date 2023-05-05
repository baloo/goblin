/// Demonstrates how to manipulate PE signatures on a UEFI binary
#[cfg(feature = "pe_pkcs7")]
use goblin::pe::PE;

use scroll::Pwrite;
use std::io::Cursor;

fn main() {
    let file = include_bytes!("../tests/bins/pe/nixos-uki.efi");
    let file = &file[..];
    let pe = PE::parse(file).unwrap();
    println!(
        "{:?}",
        pe.header
            .optional_header
            .unwrap()
            .windows_fields
            .section_alignment
    );
    let signed_data = pe
        .certificates
        .first()
        .unwrap()
        .as_signed_data()
        .unwrap()
        .unwrap();
    println!("{:?}", signed_data);

    let mut out = vec![0u8; file.len() + 8192];
    let new_len = out.pwrite(pe, 0).unwrap();

    std::fs::write("/tmp/foo.txt", &out[..file.len()]).unwrap();
    println!("{:#x?}", &out[..12]);
    let out = &out[..new_len];
    println!("file.len() = {}, out.len() = {}", file.len(), out.len());
}
