macro_rules! rva_array {
    ($self:expr, $rva:expr, $count:expr, $typ:ty) => {{
        let offset = $self.pe.rva_to_offset($rva)?;
        let array_size = $count as usize * std::mem::size_of::<$typ>();

        if $self.pe.raw.len() < offset + array_size {
            return None;
        }

        let array_raw = &$self.pe.raw[offset..offset + array_size];

        Some(unsafe {
            std::slice::from_raw_parts(
                array_raw.as_ptr() as *const $typ,
                array_raw.len() / std::mem::size_of::<$typ>(),
            )
        })
    }};
}

pub(crate) use rva_array;