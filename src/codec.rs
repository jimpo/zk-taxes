use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use ff::{PrimeField, PrimeFieldRepr};
use group::{CurveAffine, EncodedPoint};
use std::io::{self, Read, Write};

pub trait Decode<P>: Sized {
	fn read<R: Read>(reader: R, params: &P) -> io::Result<Self>;
}

pub trait Encode {
	fn write<W: Write>(&self, writer: W) -> io::Result<()>;
}

impl<P> Decode<P> for u16 {
	fn read<R: Read>(mut reader: R, _params: &P) -> io::Result<Self> {
		reader.read_u16::<LittleEndian>()
	}
}

impl Encode for u16 {
	fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
		writer.write_u16::<LittleEndian>(*self)
	}
}

impl<P> Decode<P> for u64 {
	fn read<R: Read>(mut reader: R, _params: &P) -> io::Result<Self> {
		reader.read_u64::<LittleEndian>()
	}
}

impl Encode for u64 {
	fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
		writer.write_u64::<LittleEndian>(*self)
	}
}

impl<P> Decode<P> for i64 {
	fn read<R: Read>(mut reader: R, _params: &P) -> io::Result<Self> {
		reader.read_i64::<LittleEndian>()
	}
}

impl Encode for i64 {
	fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
		writer.write_i64::<LittleEndian>(*self)
	}
}

pub fn read_curve_affine_compressed<R: Read, CA: CurveAffine>(mut reader: R) -> io::Result<CA> {
	let mut repr = CA::Compressed::empty();
	reader.read_exact(repr.as_mut())?;
	repr.into_affine()
		.map_err(|_| invalid_data_io_error("failed to decode affine curve point"))
}

pub fn write_curve_affine_compressed<W: Write, CA: CurveAffine>(mut writer: W, point: &CA)
	-> io::Result<()>
{
	writer.write_all(point.into_compressed().as_ref())
}

pub fn read_prime_field_le<R: Read, PF: PrimeField>(reader: R) -> io::Result<PF> {
	let mut repr = PF::Repr::default();
	repr.read_le(reader)?;
	PF::from_repr(repr)
		.map_err(|_| invalid_data_io_error("failed to decode prime field element"))
}

pub fn write_prime_field_le<W: Write, PF: PrimeField>(writer: W, element: &PF)
	-> io::Result<()>
{
	element.into_repr().write_le(writer)
}

pub(crate) fn invalid_data_io_error(msg: &str) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidData, msg)
}

