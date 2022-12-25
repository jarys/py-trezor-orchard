use core::fmt;
use pyo3::{
    create_exception,
    prelude::*,
    types::{PyBytes, PyDict},
    wrap_pyfunction,
};

use rand::thread_rng;
use rand_core::{CryptoRng, RngCore};
use trezor_orchard as inner;

use orchard::{
    self,
    builder::{InProgress, InProgressSignatures, PartiallyAuthorized, Unauthorized, Unproven},
    bundle::Authorized,
    circuit::Proof,
    keys::{FullViewingKey, Scope},
    note::ExtractedNoteCommitment,
    primitives::redpallas,
    primitives::redpallas::SpendAuth,
    tree::Anchor,
    Address,
};

use zcash_primitives::transaction::components::{
    amount::Amount,
    orchard::{read_v5_bundle, write_v5_bundle},
};

create_exception!(pyorchard, ProvingError, pyo3::exceptions::PyException);

#[pymodule]
fn py_trezor_orchard(py: Python, m: &PyModule) -> PyResult<()> {
    m.add("ProvingError", py.get_type::<ProvingError>())?;
    m.add_class::<OrchardInput>()?;
    m.add_class::<OrchardOutput>()?;
    m.add_class::<TrezorBuilder>()?;
    m.add_class::<Bundle>()?;
    m.add_class::<ProvingKey>()?;
    m.add_wrapped(wrap_pyfunction!(verify_bundle))?;
    Ok(())
}

fn note_from_parts(
    recipient: [u8; 43],
    value: u64,
    rho: [u8; 32],
    rseed: [u8; 32],
) -> orchard::note::Note {
    let recipient = Address::from_raw_address_bytes(&recipient).unwrap();
    let value = orchard::value::NoteValue::from_raw(value);
    let rho = orchard::note::Nullifier::from_bytes(&rho).unwrap();
    let rseed = orchard::note::RandomSeed::from_bytes(rseed, &rho).unwrap();

    orchard::note::Note::from_parts(recipient, value, rho, rseed).unwrap()
}

#[pyclass]
#[derive(Clone, Debug)]
struct OrchardInput(inner::OrchardInput);

#[pymethods]
impl OrchardInput {
    #[new]
    fn new(py: Python, msg: PyObject, path: (u32, [[u8; 32]; 32])) -> PyResult<Self> {
        Ok(OrchardInput(inner::OrchardInput {
            note: note_from_parts(
                msg.getattr(py, "recipient")?.extract(py)?,
                msg.getattr(py, "value")?.extract(py)?,
                msg.getattr(py, "rho")?.extract(py)?,
                msg.getattr(py, "rseed")?.extract(py)?,
            ),
            merkle_path: parse_path(path),
        }))
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

#[pyclass]
#[derive(Debug, Clone)]
struct OrchardOutput(inner::OrchardOutput);

#[pymethods]
impl OrchardOutput {
    #[new]
    fn new(py: Python, msg: PyObject) -> PyResult<Self> {
        let recipient: Option<String> = msg.getattr(py, "address")?.extract(py)?;
        Ok(OrchardOutput(inner::OrchardOutput {
            recipient: match recipient {
                Some(r) => trezor_orchard::Recipient::External(r),
                None => trezor_orchard::Recipient::Change,
            },
            amount: msg.getattr(py, "amount")?.extract(py)?,
            memo: msg.getattr(py, "memo")?.extract(py)?,
        }))
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

#[pyclass]
#[derive(Debug, Clone)]
struct TrezorBuilder(Option<inner::TrezorBuilder>);

#[pymethods]
impl TrezorBuilder {
    #[new]
    fn new(
        inputs: Vec<OrchardInput>,
        outputs: Vec<OrchardOutput>,
        anchor: [u8; 32],
        fvk: [u8; 96],
        shielding_seed: [u8; 32],
    ) -> Self {
        TrezorBuilder(Some(inner::TrezorBuilder {
            inputs: inputs.into_iter().map(|x| Some(x.0)).collect(),
            outputs: outputs.into_iter().map(|x| Some(x.0)).collect(),
            anchor: Anchor::from_bytes(anchor).unwrap(),
            fvk: FullViewingKey::from_bytes(&fvk).expect("invalid fvk"),
            shielding_seed,
        }))
    }

    fn build(&mut self) -> PyResult<Bundle> {
        assert!(self.0.is_some());
        let builder = std::mem::take(&mut self.0).unwrap();
        let bundle = builder.build().expect("building failed");
        Ok(Bundle(Authorization::UnprovenAndUnauthorized(Some(bundle))))
    }
}

#[allow(dead_code)]
fn print_hex(data: &[u8]) {
    for byte in data {
        print!("{:x}", byte);
    }
    println!("");
}

#[pyfunction]
fn verify_bundle(bundle: Vec<u8>) -> PyResult<()> {
    let bundle = read_v5_bundle(bundle.as_slice())
        .expect("deseralization failed")
        .expect("unwrapping failed");
    let vk = orchard::circuit::VerifyingKey::build();
    bundle
        .verify_proof(&vk)
        .map_err(|_| ProvingError::new_err("verification failed"))
}

/*
ROAD MAP:
build            :: Builder                                           -> Bundle<InProgress<Unproven, Unauthorized>, V>
create_proof     :: Bundle<InProgress<Unproven, S>, V>                -> Bundle<InProgress<Proof, S>, V>
prepare          :: Bundle<InProgress<P, Unauthorized>, V>            -> Bundle<InProgress<P, PartiallyAuthorized>, V>
sign             :: Bundle<InProgress<P, PartiallyAuthorized>, V>     -> Bundle<InProgress<P, PartiallyAuthorized>, V>
finalize         :: Bundle<InProgress<Proof, PartiallyAuthorized>, V> -> Bundle<Authorized, V>
apply_signatures :: Bundle<InProgress<Proof, Unauthorized>, V> -> Bundle<Authorized, V>
decrypt_outputs_with_keys:: &Bundle<Authorized, V> -> &[Ivks] -> Vec<(usize, IncomingViewingKey, Note, Address, [u8; 512])
*/

fn step_create_proof<S: InProgressSignatures>(
    bundle: &mut Option<orchard::Bundle<InProgress<Unproven, S>, Amount>>,
    pk: &ProvingKey,
    rng: &mut impl RngCore,
) -> Option<orchard::Bundle<InProgress<Proof, S>, Amount>> {
    Some(
        std::mem::take(bundle)
            .unwrap()
            .create_proof(&pk.0, rng)
            .expect("proving failed"),
    )
}

fn step_prepare<P: fmt::Debug, R: RngCore + CryptoRng>(
    bundle: &mut Option<orchard::Bundle<InProgress<P, Unauthorized>, Amount>>,
    rng: &mut R,
    sighash: [u8; 32],
) -> Option<orchard::Bundle<InProgress<P, PartiallyAuthorized>, Amount>> {
    Some(std::mem::take(bundle).unwrap().prepare(rng, sighash))
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
    /// The state of the `Bundle`.
    fn state(&self) -> &str {
        if !self.is_some() {
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
        let mut rng = thread_rng();
        assert!(self.is_some());
        self.0 = match &mut self.0 {
            Authorization::UnprovenAndUnauthorized(b) => {
                Authorization::ProofAndUnauthorized(step_create_proof(b, pk, &mut rng))
            }
            Authorization::UnprovenAndPartiallyAuthorized(b) => {
                Authorization::ProofAndPartiallyAuthorized(step_create_proof(b, pk, &mut rng))
            }
            _ => return Err(ProvingError::new_err("cannot create a proof at this state")),
        };
        Ok(())
    }

    fn prepare(&mut self, sighash: [u8; 32]) -> PyResult<()> {
        let mut rng = thread_rng();
        assert!(self.is_some());
        self.0 = match &mut self.0 {
            Authorization::UnprovenAndUnauthorized(b) => {
                Authorization::UnprovenAndPartiallyAuthorized(step_prepare(b, &mut rng, sighash))
            }
            Authorization::ProofAndUnauthorized(b) => {
                Authorization::ProofAndPartiallyAuthorized(step_prepare(b, &mut rng, sighash))
            }
            _ => return Err(ProvingError::new_err("cannot prepaire at this state")),
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
            _ => {
                return Err(ProvingError::new_err(
                    "cannot append signatures at this state",
                ))
            }
        };
        Ok(())
    }

    fn finalize(&mut self) -> PyResult<()> {
        assert!(self.is_some());
        self.0 = match &mut self.0 {
            Authorization::ProofAndPartiallyAuthorized(b) => {
                Authorization::Authorized(step_finalize(b))
            }
            _ => return Err(ProvingError::new_err("cannot finalize at this state")),
        };
        Ok(())
    }

    fn serialized<'a>(&self, py: Python<'a>) -> PyResult<&'a PyBytes> {
        let mut serialized = Vec::<u8>::new();
        match &self.0 {
            Authorization::Authorized(b) => {
                write_v5_bundle(b.as_ref(), &mut serialized).expect("cannot serialize")
            }
            _ => return Err(ProvingError::new_err("cannot serialize at this state")),
        };
        Ok(PyBytes::new(py, &serialized))
    }

    fn decrypt_outputs_with_fvk<'a>(
        &self,
        py: Python<'a>,
        fvk: [u8; 96],
    ) -> PyResult<Vec<(&'a PyDict, &'a PyBytes)>> {
        let fvk = FullViewingKey::from_bytes(&fvk).expect("invalid fvk");
        let keys = [fvk.to_ivk(Scope::External), fvk.to_ivk(Scope::Internal)];
        let res = match &self.0 {
            Authorization::Authorized(Some(b)) => b.decrypt_outputs_with_keys(&keys),
            _ => return Err(ProvingError::new_err("cannot decrypt at this state")),
        };
        res.iter()
            .map(|(_, _, note, _, _)| {
                (
                    note_to_dict(&note, py),
                    PyBytes::new(
                        py,
                        &ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
                    ),
                )
            })
            .map(|(x, y)| match x {
                Ok(z) => Ok((z, y)),
                Err(z) => Err(z),
            })
            .collect()
    }
}

fn note_to_dict<'a>(note: &orchard::note::Note, py: Python<'a>) -> PyResult<&'a PyDict> {
    let dict = PyDict::new(py).to_owned();
    dict.set_item(
        "recipient",
        PyBytes::new(py, &note.recipient().to_raw_address_bytes()),
    )?;
    dict.set_item("value", note.value().inner())?;
    dict.set_item("rho", PyBytes::new(py, &note.rho().to_bytes()))?;
    dict.set_item("rseed", PyBytes::new(py, note.rseed().as_bytes()))?;
    Ok(dict)
}
