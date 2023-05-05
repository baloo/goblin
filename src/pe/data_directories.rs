use crate::error;
use core::ops::Deref;
use scroll::{ctx, Pread, Pwrite, SizeWith};

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default, Pread, Pwrite, SizeWith)]
pub struct DataDirectoryInner {
    pub virtual_address: u32,
    pub size: u32,
}
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct DataDirectory {
    pub inner: DataDirectoryInner,
    pub(crate) offset: usize,
}

pub const SIZEOF_DATA_DIRECTORY: usize = 8;
const NUM_DATA_DIRECTORIES: usize = 16;

impl DataDirectory {
    pub fn parse(bytes: &[u8], offset: &mut usize) -> error::Result<Self> {
        let inner = bytes.gread_with(offset, scroll::LE)?;
        Ok(DataDirectory {
            inner,
            offset: *offset,
        })
    }

    pub fn data<'a>(&self, pe: &'a [u8]) -> error::Result<&'a [u8]> {
        let start = self.offset;
        let end = start + usize::try_from(self.inner.size)?;

        Ok(pe.get(start..end).ok_or(error::Error::Malformed(
            "Invalid data directory range".into(),
        ))?)
    }
}

impl Deref for DataDirectory {
    type Target = DataDirectoryInner;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct DataDirectories {
    pub data_directories: [Option<DataDirectory>; NUM_DATA_DIRECTORIES],
}

impl ctx::TryIntoCtx<scroll::Endian> for DataDirectories {
    type Error = error::Error;

    fn try_into_ctx(self, bytes: &mut [u8], ctx: scroll::Endian) -> Result<usize, Self::Error> {
        let offset = &mut 0;
        for opt_dd in self.data_directories {
            if let Some(dd) = opt_dd {
                bytes.gwrite_with(dd.inner, offset, ctx)?;
            } else {
                let zero: Vec<u8> = vec![0; SIZEOF_DATA_DIRECTORY];
                bytes.gwrite(&zero[..], offset)?;
            }
        }
        Ok(NUM_DATA_DIRECTORIES * SIZEOF_DATA_DIRECTORY)
    }
}

impl DataDirectories {
    pub fn parse(bytes: &[u8], count: usize, offset: &mut usize) -> error::Result<Self> {
        let mut data_directories = [None; NUM_DATA_DIRECTORIES];
        if count > NUM_DATA_DIRECTORIES {
            return Err(error::Error::Malformed(format!(
                "data directory count ({}) is greater than maximum number of data directories ({})",
                count, NUM_DATA_DIRECTORIES
            )));
        }
        for dir in data_directories.iter_mut().take(count) {
            let dd = DataDirectory::parse(bytes, offset)?;
            let dd = if dd.virtual_address == 0 && dd.size == 0 {
                None
            } else {
                Some(dd)
            };
            *dir = dd;
        }
        Ok(DataDirectories { data_directories })
    }
    pub fn get_export_table(&self) -> &Option<DataDirectory> {
        let idx = 0;
        &self.data_directories[idx]
    }
    pub fn get_import_table(&self) -> &Option<DataDirectory> {
        let idx = 1;
        &self.data_directories[idx]
    }
    pub fn get_resource_table(&self) -> &Option<DataDirectory> {
        let idx = 2;
        &self.data_directories[idx]
    }
    pub fn get_exception_table(&self) -> &Option<DataDirectory> {
        let idx = 3;
        &self.data_directories[idx]
    }
    pub fn get_certificate_table(&self) -> &Option<DataDirectory> {
        let idx = 4;
        &self.data_directories[idx]
    }
    pub fn get_base_relocation_table(&self) -> &Option<DataDirectory> {
        let idx = 5;
        &self.data_directories[idx]
    }
    pub fn get_debug_table(&self) -> &Option<DataDirectory> {
        let idx = 6;
        &self.data_directories[idx]
    }
    pub fn get_architecture(&self) -> &Option<DataDirectory> {
        let idx = 7;
        &self.data_directories[idx]
    }
    pub fn get_global_ptr(&self) -> &Option<DataDirectory> {
        let idx = 8;
        &self.data_directories[idx]
    }
    pub fn get_tls_table(&self) -> &Option<DataDirectory> {
        let idx = 9;
        &self.data_directories[idx]
    }
    pub fn get_load_config_table(&self) -> &Option<DataDirectory> {
        let idx = 10;
        &self.data_directories[idx]
    }
    pub fn get_bound_import_table(&self) -> &Option<DataDirectory> {
        let idx = 11;
        &self.data_directories[idx]
    }
    pub fn get_import_address_table(&self) -> &Option<DataDirectory> {
        let idx = 12;
        &self.data_directories[idx]
    }
    pub fn get_delay_import_descriptor(&self) -> &Option<DataDirectory> {
        let idx = 13;
        &self.data_directories[idx]
    }
    pub fn get_clr_runtime_header(&self) -> &Option<DataDirectory> {
        let idx = 14;
        &self.data_directories[idx]
    }
}
