use crate::certificate::AnonymousCertificate;
use crate::codec::{Decode, Encode, invalid_data_io_error};

use bellman::groth16::Proof;
use byteorder::{LittleEndian, ByteOrder};
use std::convert::TryFrom;
use std::fmt::{Debug, Display};
use std::io::{self, Read, Write};
use zcash_primitives::jubjub::{edwards, JubjubEngine, Unknown};

pub type Value = u64;
pub type Nullifier = [u8; 32];

pub trait BlockNumber: Debug + Display + Decode<()> + Encode + Clone {}
impl BlockNumber for u64 {}

#[derive(PartialEq, Clone)]
pub struct Transaction<E, BN>
	where E: JubjubEngine
{
	pub inputs: Vec<TransactionInputBundle<E>>,
	pub outputs: Vec<TransactionOutput<E>>,
	pub issuance: i64,

	/// The state of the coin accumulator used to validate inputs
	pub accumulator_state_block_number: BN,
}

impl<E, BN> Transaction<E, BN>
	where
		E: JubjubEngine,
		BN: BlockNumber,
{
	pub fn read<R: Read>(mut reader: R, params: &E::Params) -> io::Result<Self> {
		let inputs_length = u16::read(&mut reader, &())
			.map_err(|_| invalid_data_io_error("failed to decode input bundles length"))?;
		let inputs = (0..inputs_length)
			.map(|_| <TransactionInputBundle<E>>::read(&mut reader, params))
			.collect::<Result<_, _>>()?;

		let outputs_length = u16::read(&mut reader, &())
			.map_err(|_| invalid_data_io_error("failed to decode outputs length"))?;
		let outputs = (0..outputs_length)
			.map(|_| <TransactionOutput<E>>::read(&mut reader, params))
			.collect::<Result<_, _>>()?;

		let issuance = i64::read(&mut reader, &())
			.map_err(|_| invalid_data_io_error("failed to decode issuance"))?;
		let accumulator_state_block_number = BN::read(&mut reader, &())
			.map_err(|_| invalid_data_io_error("failed to decode block number"))?;

		Ok(Transaction {
			inputs,
			outputs,
			issuance,
			accumulator_state_block_number,
		})
	}

	pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
		u16::try_from(self.inputs.len())
			.map_err(|_| invalid_data_io_error("transaction has too many input bundles"))?
			.write(&mut writer)?;
		for input in self.inputs.iter() {
			input.write(&mut writer)?;
		}

		u16::try_from(self.outputs.len())
			.map_err(|_| invalid_data_io_error("transaction has too many outputs"))?
			.write(&mut writer)?;
		for output in self.outputs.iter() {
			output.write(&mut writer)?;
		}

		self.issuance.write(&mut writer)?;
		self.accumulator_state_block_number.write(&mut writer)?;

		Ok(())
	}
}

#[derive(PartialEq, Clone)]
pub struct TransactionInput<E>
	where E: JubjubEngine
{
	pub value_comm: edwards::Point<E, Unknown>,
	pub nullifier: Nullifier,
	pub proof: Proof<E>,
}

impl<E> TransactionInput<E>
	where E: JubjubEngine
{
	pub fn read<R: Read>(mut reader: R, params: &E::Params) -> io::Result<Self> {
		let value_comm = <edwards::Point<E, Unknown>>::read(&mut reader, params)?;
		let mut nullifier = Nullifier::default();
		reader.read(&mut nullifier[..])?;
		let proof = <Proof<E>>::read(&mut reader)?;

		Ok(TransactionInput {
			value_comm,
			nullifier,
			proof,
		})
	}

	pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
		self.value_comm.write(&mut writer)?;
		writer.write(&self.nullifier[..])?;
		self.proof.write(&mut writer)?;
		Ok(())
	}
}

#[derive(PartialEq, Clone)]
pub struct TransactionOutput<E>
	where E: JubjubEngine
{
	pub value_comm: edwards::Point<E, Unknown>,
	pub certificate: AnonymousCertificate<E>,
	// pub enc_details: ,
	// pub enc_details_proof: ,
}

impl<E> TransactionOutput<E>
	where E: JubjubEngine
{
	pub fn read<R: Read>(mut reader: R, params: &E::Params) -> io::Result<Self> {
		let value_comm = <edwards::Point<E, Unknown>>::read(&mut reader, params)?;
		let certificate = AnonymousCertificate::read(&mut reader, params)?;

		Ok(TransactionOutput {
			value_comm,
			certificate,
		})
	}

	pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
		self.value_comm.write(&mut writer)?;
		self.certificate.write(&mut writer)?;
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

#[derive(PartialEq, Clone)]
pub struct TransactionInputBundle<E>
	where E: JubjubEngine
{
	pub pubkey: (edwards::Point<E, Unknown>, edwards::Point<E, Unknown>),
	pub inputs: Vec<TransactionInput<E>>,
	pub change_comm: edwards::Point<E, Unknown>,
	pub proof: Proof<E>,
}

impl<E> TransactionInputBundle<E>
	where E: JubjubEngine
{
	pub fn read<R: Read>(mut reader: R, params: &E::Params) -> io::Result<Self> {
		let pubkey = (
			<edwards::Point<E, Unknown>>::read(&mut reader, params)?,
			<edwards::Point<E, Unknown>>::read(&mut reader, params)?
		);

		let inputs_length = u16::read(&mut reader, &())
			.map_err(|_| invalid_data_io_error("failed to decode inputs length"))?;
		let inputs = (0..inputs_length)
			.map(|_| <TransactionInput<E>>::read(&mut reader, params))
			.collect::<Result<_, _>>()?;

		let change_comm = <edwards::Point<E, Unknown>>::read(&mut reader, params)?;
		let proof = <Proof<E>>::read(&mut reader)?;

		Ok(TransactionInputBundle {
			pubkey,
			inputs,
			change_comm,
			proof,
		})
	}

	pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
		self.pubkey.0.write(&mut writer)?;
		self.pubkey.1.write(&mut writer)?;

		u16::try_from(self.inputs.len())
			.map_err(|_| invalid_data_io_error("transaction input bundle has too many inputs"))?
			.write(&mut writer)?;
		for input in self.inputs.iter() {
			input.write(&mut writer)?;
		}

		self.change_comm.write(&mut writer)?;
		self.proof.write(&mut writer)?;
		Ok(())
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

