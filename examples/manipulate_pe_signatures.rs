/// Demonstrates how to manipulate PE signatures on a UEFI binary
#[cfg(feature = "pe_pkcs7")]
use goblin::pe::PE;

fn main() {
    let file = include_bytes!("../tests/bins/pe/nixos-uki.efi");
    let file = &file[..];
    let pe = PE::parse(file).unwrap();
    println!("{:?}", pe.certificates.first().unwrap().as_signed_data().unwrap().unwrap());
}
