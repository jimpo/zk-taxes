use bellman::groth16::Proof;
use byteorder::{LittleEndian, ByteOrder};
use parity_codec::{Codec, Compact, Encode, Decode};
use std::io::{self, Read, Write};
use std::fmt::{Debug, Display};
use zcash_primitives::jubjub::{edwards, JubjubEngine, Unknown};

pub type Value = u64;
pub type Nullifier = [u8; 32];

pub trait BlockNumber: Debug + Display + Clone {}
impl BlockNumber for u64 {}

#[derive(PartialEq, Clone)]
pub struct Transaction<E, BN>
	where E: JubjubEngine
{
	pub inputs: Vec<TransactionInput<E>>,
	pub outputs: Vec<TransactionOutput<E>>,
	pub issuance: i64,

	/// The state of the coin accumulator used to validate inputs
	pub accumulator_state_block_number: BN,
}

impl<E, BN> Transaction<E, BN>
	where
		E: JubjubEngine,
		BN: Codec,
{
	pub fn read<R: Read>(mut reader: R, params: &E::Params) -> io::Result<Self> {
		let inputs_length = <Compact<u32>>::decode(&mut reader)
			.ok_or_else(|| {
				io::Error::new(io::ErrorKind::InvalidData, "failed to decode inputs length")
			})?;
		let inputs = (0..inputs_length.0)
			.map(|_| <TransactionInput<E>>::read(&mut reader, params))
			.collect::<Result<_, _>>()?;

		let outputs_length = <Compact<u32>>::decode(&mut reader)
			.ok_or_else(|| {
				io::Error::new(io::ErrorKind::InvalidData, "failed to decode outputs length")
			})?;
		let outputs = (0..outputs_length.0)
			.map(|_| <TransactionOutput<E>>::read(&mut reader, params))
			.collect::<Result<_, _>>()?;

		let issuance = Decode::decode(&mut reader)
			.ok_or_else(|| {
				io::Error::new(io::ErrorKind::InvalidData, "failed to decode issuance")
			})?;
		let accumulator_state_block_number = BN::decode(&mut reader)
			.ok_or_else(|| {
				io::Error::new(io::ErrorKind::InvalidData, "failed to decode block number")
			})?;

		Ok(Transaction {
			inputs,
			outputs,
			issuance,
			accumulator_state_block_number,
		})
	}

	pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
		Compact(self.inputs.len() as u32).encode_to(&mut writer);
		for input in self.inputs.iter() {
			input.write(&mut writer)?;
		}

		Compact(self.outputs.len() as u32).encode_to(&mut writer);
		for output in self.outputs.iter() {
			output.write(&mut writer)?;
		}

		self.issuance.encode_to(&mut writer);
		self.accumulator_state_block_number.encode_to(&mut writer);

		Ok(())
	}
}

#[derive(PartialEq, Clone)]
pub struct TransactionInput<E>
	where E: JubjubEngine
{
	pub value_comm: edwards::Point<E, Unknown>,
	pub pubkey: (edwards::Point<E, Unknown>, edwards::Point<E, Unknown>),
	pub nullifier: Nullifier,
	pub proof: Proof<E>,
}

impl<E> TransactionInput<E>
	where E: JubjubEngine
{
	pub fn read<R: Read>(mut reader: R, params: &E::Params) -> io::Result<Self> {
		let value_comm = <edwards::Point<E, Unknown>>::read(&mut reader, params)?;
		let pubkey = (
			<edwards::Point<E, Unknown>>::read(&mut reader, params)?,
			<edwards::Point<E, Unknown>>::read(&mut reader, params)?
		);
		let mut nullifier = Nullifier::default();
		reader.read(&mut nullifier[..])?;
		let proof = <Proof<E>>::read(&mut reader)?;

		Ok(TransactionInput {
			value_comm,
			pubkey,
			nullifier,
			proof,
		})
	}

	pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
		self.value_comm.write(&mut writer)?;
		self.pubkey.0.write(&mut writer)?;
		self.pubkey.1.write(&mut writer)?;
		self.nullifier.encode_to(&mut writer);
		self.proof.write(&mut writer)?;
		Ok(())
	}
}

#[derive(PartialEq, Clone)]
pub struct TransactionOutput<E>
	where E: JubjubEngine
{
	pub value_comm: edwards::Point<E, Unknown>,
	// pub credential: Vec<u8>,
	// pub credential_proof: ,
	// pub enc_details: ,
	// pub enc_details_proof: ,
}

impl<E> TransactionOutput<E>
	where E: JubjubEngine
{
	pub fn read<R: Read>(mut reader: R, params: &E::Params) -> io::Result<Self> {
		let value_comm = <edwards::Point<E, Unknown>>::read(&mut reader, params)?;

		Ok(TransactionOutput {
			value_comm,
		})
	}

	pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
		self.value_comm.write(&mut writer)?;
		Ok(())
	}

	pub fn coin(&self, position: u64) -> Coin<E> {
		Coin {
			position,
			value_comm: self.value_comm.clone(),
			pubkey: (edwards::Point::zero(), edwards::Point::zero()),
		}
	}

	pub fn into_coin(self, position: u64) -> Coin<E> {
		Coin {
			position,
			value_comm: self.value_comm,
			pubkey: (edwards::Point::zero(), edwards::Point::zero()),
		}
	}
}

pub struct Coin<E>
	where E: JubjubEngine
{
	pub position: u64,
	pub value_comm: edwards::Point<E, Unknown>,
	pub pubkey: (edwards::Point<E, Unknown>, edwards::Point<E, Unknown>),
}

impl<E> Coin<E>
	where E: JubjubEngine
{
	pub fn read<R: Read>(mut reader: R, params: &E::Params) -> io::Result<Self> {
		let mut position_bytes = [0u8; 8];
		reader.read(&mut position_bytes[..])?;

		let position = LittleEndian::read_u64(&position_bytes);
		let value_comm = <edwards::Point<E, Unknown>>::read(&mut reader, params)?;
		let pubkey = (
			<edwards::Point<E, Unknown>>::read(&mut reader, params)?,
			<edwards::Point<E, Unknown>>::read(&mut reader, params)?
		);

		Ok(Coin {
			position,
			value_comm,
			pubkey,
		})
	}

	pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
		let mut position_bytes = [0u8; 8];
		LittleEndian::write_u64(&mut position_bytes[..], self.position);

		writer.write(&position_bytes)?;
		self.value_comm.write(&mut writer)?;
		self.pubkey.0.write(&mut writer)?;
		self.pubkey.1.write(&mut writer)?;
		Ok(())
	}
}
