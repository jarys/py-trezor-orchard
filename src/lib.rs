use pyo3::{create_exception, prelude::*, wrap_pyfunction};

use nonempty::NonEmpty;
use rand::{rngs::StdRng, thread_rng, CryptoRng, SeedableRng};
use rand_core::RngCore;
use std::fmt;

use ff::{Field, PrimeField};
use incrementalmerkletree;
use subtle::CtOption;

use zcash_primitives::transaction::components::{amount::Amount, orchard::write_v5_bundle};

use orchard::{
    builder::MaybeSigned,
    builder::{
        Builder, InProgress, InProgressSignatures, PartiallyAuthorized, Unauthorized, Unproven,
    },
    bundle::Authorized,
    bundle::{self, Flags},
    circuit::{Circuit, Proof},
    keys::{FullViewingKey, SpendingKey},
    primitives::redpallas::{self, Binding, Signature, SpendAuth},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment, ValueSum},
    Address,
};

create_exception!(pyorchard, StateError, pyo3::exceptions::PyException);

#[pymodule]
fn pyorchard(py: Python, m: &PyModule) -> PyResult<()> {
    m.add("StateError", py.get_type::<StateError>())?;
    m.add_class::<Note>()?;
    m.add_class::<Bundle>()?;
    m.add_class::<ProvingKey>()?;
    m.add_class::<Witness>()?;
    //m.add_wrapped(wrap_pyfunction!(experiment))?;
    m.add_wrapped(wrap_pyfunction!(parse_trezor_message))?;
    Ok(())
}

//create_exception!(procmaps, ParseError, PyException);

#[pyclass]
#[derive(Clone, Debug)]
struct Note(orchard::note::Note);

#[pymethods]
impl Note {
    #[staticmethod]
    fn from_parts(recipient: [u8; 43], value: u64, rho: [u8; 32], rseed: [u8; 32]) -> Self {
        let recipient = Address::from_raw_address_bytes(&recipient).unwrap();
        let value = orchard::value::NoteValue::from_raw(value);
        let rho = orchard::note::Nullifier::from_bytes(&rho).unwrap();
        let rseed = orchard::note::RandomSeed::from_bytes(rseed, &rho).unwrap();
        Note(orchard::note::Note::from_parts(
            recipient, value, rho, rseed,
        ))
    }

    #[staticmethod]
    fn from_obj(py: Python, obj: PyObject) -> PyResult<Self> {
        Ok(Note::from_parts(
            obj.getattr(py, "recipient")?.extract(py)?,
            obj.getattr(py, "value")?.extract(py)?,
            obj.getattr(py, "rho")?.extract(py)?,
            obj.getattr(py, "rseed")?.extract(py)?,
        ))
    }
}

#[pyclass]
#[derive(Clone, Debug)]
struct Action(orchard::Action<()>);

#[pymethods]
impl Action {
    //#[staticmethod]
    //fn from_parts(witness: Witness, encrypted_note: TransmittedNoteCiphertext) {}

    #[staticmethod]
    fn from_obj(py: Python, obj: PyObject) -> PyResult<Self> {
        let nf: [u8; 32] = obj.getattr(py, "nf")?.extract(py)?;
        let nf = orchard::note::Nullifier::from_bytes(&nf).unwrap();
        let rk: [u8; 32] = obj.getattr(py, "rk")?.extract(py)?;
        let rk = orchard::primitives::redpallas::VerificationKey::<
            orchard::primitives::redpallas::SpendAuth,
        >::try_from(rk)
        .unwrap();
        let cmx: [u8; 32] = obj.getattr(py, "cmx")?.extract(py)?;
        let cmx = orchard::note::ExtractedNoteCommitment::from_bytes(&cmx).unwrap();
        let encrypted_note = obj.getattr(py, "encrypted_note")?;
        let encrypted_note = orchard::note::TransmittedNoteCiphertext {
            epk_bytes: encrypted_note.getattr(py, "epk_bytes")?.extract(py)?,
            enc_ciphertext: encrypted_note.getattr(py, "enc_ciphertext")?.extract(py)?,
            out_ciphertext: encrypted_note.getattr(py, "out_ciphertext")?.extract(py)?,
        };
        let cv_net: [u8; 32] = obj.getattr(py, "cv")?.extract(py)?;
        let cv_net = orchard::value::ValueCommitment::from_bytes(&cv_net).unwrap();
        Ok(Action(orchard::Action::from_parts(
            nf,
            rk,
            cmx,
            encrypted_note,
            cv_net,
            (),
        )))
    }
}

#[pyclass]
#[derive(Clone, Debug)]
struct Witness {
    merkle_path: Option<(u32, [[u8; 32]; 32])>,
    input_note: orchard::note::Note,
    output_note: orchard::note::Note,
    fvk: FullViewingKey,
    alpha: pasta_curves::Fq,
    rcv: [u8; 32],
}

impl Witness {
    fn add_dummy_merkle_path(&mut self) {
        assert!(self.merkle_path.is_none());
        let mut rng = thread_rng();
        self.merkle_path = Some((
            rng.next_u32(),
            [(); 32].map(|_| pasta_curves::Fp::random(&mut rng).to_repr()),
        ));
    }
}

#[pymethods]
impl Witness {
    #[staticmethod]
    fn from_obj(py: Python, obj: PyObject) -> PyResult<Self> {
        let input_note = obj.getattr(py, "input_note")?;
        let input_note = Note::from_obj(py, input_note)?.0;
        let output_note = obj.getattr(py, "output_note")?;
        let output_note = Note::from_obj(py, output_note)?.0;
        let fvk: [u8; 96] = obj.getattr(py, "fvk")?.extract(py)?;
        let fvk = orchard::keys::FullViewingKey::from_bytes(&fvk).unwrap();
        let alpha: [u8; 32] = obj.getattr(py, "alpha")?.extract(py)?;
        let alpha = pasta_curves::Fq::from_repr(alpha).unwrap();
        let rcv: [u8; 32] = obj.getattr(py, "rcv")?.extract(py)?;
        //let rcv = orchard::value::ValueCommitTrapdoor::from_bytes(rcv.clone()).unwrap();
        Ok(Witness {
            merkle_path: None,
            input_note,
            output_note,
            fvk,
            alpha,
            rcv,
        })
    }
    fn add_merkle_path(&mut self, merkle_path: (u32, [[u8; 32]; 32])) {
        assert!(self.merkle_path.is_none());
        self.merkle_path = Some(merkle_path);
    }
}

fn parse_path(path: (u32, [[u8; 32]; 32])) -> orchard::tree::MerklePath {
    let auth_path: [orchard::tree::MerkleHashOrchard; 32] = path
        .1
        .into_iter()
        .map(|x| orchard::tree::MerkleHashOrchard::from_bytes(&x).unwrap())
        .collect::<Vec<orchard::tree::MerkleHashOrchard>>()
        .try_into()
        .unwrap();
    orchard::tree::MerklePath::from_parts(path.0, auth_path)
}

#[pyfunction]
fn parse_trezor_message(py: Python, msg: PyObject) -> PyResult<(Action, Witness)> {
    let witness = msg.getattr(py, "proof_witness")?;
    let mut witness = Witness::from_obj(py, witness)?;

    let dummy_ask: Option<[u8; 32]> = msg.getattr(py, "dummy_ask")?.extract(py).ok();
    let dummy_ask = dummy_ask.map(|ask| SpendingKey::from_bytes(ask).unwrap());
    if dummy_ask.is_some() {
        witness.add_dummy_merkle_path();
    }

    let action = msg.getattr(py, "action")?;
    let action = Action::from_obj(py, action)?;

    Ok((action, witness))
}

fn step_create_proof<S: InProgressSignatures>(
    bundle: &mut Option<orchard::Bundle<InProgress<Unproven, S>, Amount>>,
    pk: &ProvingKey,
) -> Option<orchard::Bundle<InProgress<Proof, S>, Amount>> {
    Some(
        std::mem::take(bundle)
            .unwrap()
            .create_proof(&pk.0, thread_rng())
            .expect("proving failed"),
    )
}

fn step_prepare<P: fmt::Debug>(
    bundle: &mut Option<orchard::Bundle<InProgress<P, Unauthorized>, Amount>>,
    sighash: [u8; 32],
) -> Option<orchard::Bundle<InProgress<P, PartiallyAuthorized>, Amount>> {
    Some(
        std::mem::take(bundle)
            .unwrap()
            .prepare(thread_rng(), sighash),
    )
}

fn step_append_signatures<P: fmt::Debug>(
    bundle: &mut Option<orchard::Bundle<InProgress<P, PartiallyAuthorized>, Amount>>,
    signatures: Vec<[u8; 64]>,
) -> Option<orchard::Bundle<InProgress<P, PartiallyAuthorized>, Amount>> {
    let signatures: Vec<redpallas::Signature<SpendAuth>> = signatures
        .into_iter()
        .map(redpallas::Signature::<redpallas::SpendAuth>::from)
        .collect();
    Some(
        std::mem::take(bundle)
            .unwrap()
            .append_signatures(&signatures)
            .expect("cannot append a signature"),
    )
}

fn step_finalize(
    bundle: &mut Option<orchard::Bundle<InProgress<Proof, PartiallyAuthorized>, Amount>>,
) -> Option<orchard::Bundle<Authorized, Amount>> {
    Some(
        std::mem::take(bundle)
            .unwrap()
            .finalize()
            .expect("cannot finalize"),
    )
}

enum Authorization {
    UnprovenAndUnauthorized(Option<orchard::Bundle<InProgress<Unproven, Unauthorized>, Amount>>),
    UnprovenAndPartiallyAuthorized(
        Option<orchard::Bundle<InProgress<Unproven, PartiallyAuthorized>, Amount>>,
    ),
    ProofAndUnauthorized(Option<orchard::Bundle<InProgress<Proof, Unauthorized>, Amount>>),
    ProofAndPartiallyAuthorized(
        Option<orchard::Bundle<InProgress<Proof, PartiallyAuthorized>, Amount>>,
    ),
    Authorized(Option<orchard::Bundle<orchard::bundle::Authorized, Amount>>),
}

#[pyclass]
struct Bundle(Authorization);

// private methods
impl Bundle {
    fn is_some(&self) -> bool {
        match &self.0 {
            Authorization::UnprovenAndUnauthorized(o) => o.is_some(),
            Authorization::UnprovenAndPartiallyAuthorized(o) => o.is_some(),
            Authorization::ProofAndUnauthorized(o) => o.is_some(),
            Authorization::ProofAndPartiallyAuthorized(o) => o.is_some(),
            Authorization::Authorized(o) => o.is_some(),
        }
    }
}

#[pymethods]
impl Bundle {
    #[staticmethod]
    fn from_hww_data(
        anchor: [u8; 32],
        spends_enabled: bool,
        outputs_enabled: bool,
        actions: Vec<Action>,
        witnesses: Vec<Witness>,
        spend_auth_signatures: Vec<[u8; 64]>,
        binding_signature: [u8; 64],
    ) -> Bundle {
        let anchor = Anchor::from_bytes(anchor).unwrap();
        let value_balance: i64 = witnesses
            .iter()
            .fold(Some(ValueSum::default()), |acc, w| {
                acc? + (w.input_note.value() - w.output_note.value())
            })
            .unwrap()
            .try_into()
            .unwrap();
        let value_balance: Amount = value_balance.try_into().unwrap();
        //let bsk = witnesses.iter().map(|w| &w.rcv).sum();
        //let bsk = redpallas::SigningKey::<Binding>::try_from(bsk).unwrap();
        let circuits = witnesses
            .into_iter()
            .map(|w| {
                let rcv = orchard::value::ValueCommitTrapdoor::from_bytes(w.rcv.clone()).unwrap();
                orchard::circuit::Circuit::from_action_context(
                    parse_path(w.merkle_path.expect("Missing merkle path")),
                    w.input_note,
                    w.output_note,
                    w.fvk,
                    w.alpha,
                    rcv,
                )
            })
            .collect::<Option<Vec<Circuit>>>()
            .unwrap();
        let signatures: Vec<Signature<SpendAuth>> = spend_auth_signatures
            .into_iter()
            .map(Signature::from)
            .collect();
        let actions: Vec<orchard::Action<MaybeSigned>> = actions
            .clone()
            .into_iter()
            .zip(signatures.into_iter())
            .map(|(action, signature)| action.0.map(|()| MaybeSigned::Signature(signature)))
            .collect();
        let authorization = InProgress {
            proof: Unproven { circuits },
            sigs: PartiallyAuthorized {
                binding_signature: Signature::<Binding>::from(binding_signature),
                sighash: [0u8; 32], // mock sighash
            },
        };
        let flags = Flags::from_parts(spends_enabled, outputs_enabled);
        Bundle(Authorization::UnprovenAndPartiallyAuthorized(Some(
            bundle::Bundle::from_parts(
                NonEmpty::from_vec(actions).unwrap(),
                flags,
                value_balance,
                anchor,
                authorization,
            ),
        )))
    }

    /// The state of the `Bundle`.
    fn state(&self) -> &str {
        if self.is_some() {
            "Broken"
        } else {
            match &self.0 {
                Authorization::UnprovenAndUnauthorized(_) => "Unproven & Unauthorized",
                Authorization::UnprovenAndPartiallyAuthorized(_) => {
                    "Unproven & PartiallyAuthorized"
                }
                Authorization::ProofAndUnauthorized(_) => "Proven & Unauthorized",
                Authorization::ProofAndPartiallyAuthorized(_) => "Proven & PartiallyAuthorized",
                Authorization::Authorized(_) => "Authorized",
            }
        }
    }

    fn create_proof(&mut self, pk: &ProvingKey) -> PyResult<()> {
        assert!(self.is_some());
        self.0 = match &mut self.0 {
            Authorization::UnprovenAndUnauthorized(b) => {
                Authorization::ProofAndUnauthorized(step_create_proof(b, pk))
            }
            Authorization::UnprovenAndPartiallyAuthorized(b) => {
                Authorization::ProofAndPartiallyAuthorized(step_create_proof(b, pk))
            }
            _ => panic!("cannot create a proof at this state"),
        };
        Ok(())
    }

    fn prepare(&mut self, sighash: [u8; 32]) -> PyResult<()> {
        assert!(self.is_some());
        self.0 = match &mut self.0 {
            Authorization::UnprovenAndUnauthorized(b) => {
                Authorization::UnprovenAndPartiallyAuthorized(step_prepare(b, sighash))
            }
            Authorization::ProofAndUnauthorized(b) => {
                Authorization::ProofAndPartiallyAuthorized(step_prepare(b, sighash))
            }
            _ => panic!("cannot prepare at this state"),
        };
        Ok(())
    }

    fn append_signatures(&mut self, signatures: Vec<[u8; 64]>) -> PyResult<()> {
        assert!(self.is_some());
        self.0 = match &mut self.0 {
            Authorization::UnprovenAndPartiallyAuthorized(b) => {
                Authorization::UnprovenAndPartiallyAuthorized(step_append_signatures(b, signatures))
            }
            Authorization::ProofAndPartiallyAuthorized(b) => {
                Authorization::ProofAndPartiallyAuthorized(step_append_signatures(b, signatures))
            }
            _ => panic!("cannot append a signature at this state"),
        };
        Ok(())
    }

    fn finalize(&mut self) -> PyResult<()> {
        assert!(self.is_some());
        self.0 = match &mut self.0 {
            Authorization::ProofAndPartiallyAuthorized(b) => {
                Authorization::Authorized(step_finalize(b))
            }
            _ => panic!("cannot finalize at this state"),
        };
        Ok(())
    }

    fn serialized(&self, py: Python) -> Vec<u8> {
        let mut serialized = Vec::<u8>::new();
        match &self.0 {
            Authorization::Authorized(b) => {
                write_v5_bundle(b.as_ref(), &mut serialized).expect("cannot serialize")
            }
            _ => panic!("cannot serialize at this state"),
        };
        serialized
    }
}

#[pyclass]
struct ProvingKey(orchard::circuit::ProvingKey);

#[pymethods]
impl ProvingKey {
    #[staticmethod]
    fn build() -> Self {
        ProvingKey(orchard::circuit::ProvingKey::build())
    }
}
