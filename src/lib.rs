use pyo3::{create_exception, prelude::*, wrap_pyfunction};

use rand::thread_rng;
use rand_core::RngCore;

use ff::{Field, PrimeField};

use orchard::{
    circuit::{Circuit, Instance, Proof},
    keys::{FullViewingKey, SpendValidatingKey},
    note::{ExtractedNoteCommitment, Nullifier},
    primitives::redpallas::{SpendAuth, VerificationKey},
    tree::Anchor,
    value::{ValueCommitTrapdoor, ValueCommitment, ValueSum},
    Address,
};

use zcash_primitives::transaction::components::orchard::read_v5_bundle;

create_exception!(pyorchard, ProvingError, pyo3::exceptions::PyException);

#[pymodule]
fn trezor_orchard(py: Python, m: &PyModule) -> PyResult<()> {
    m.add("ProvingError", py.get_type::<ProvingError>())?;
    m.add_class::<Note>()?;
    m.add_class::<Prover>()?;
    m.add_class::<ProvingKey>()?;
    m.add_class::<Witness>()?;
    m.add_class::<Note>()?;
    m.add_wrapped(wrap_pyfunction!(verify_bundle))?;
    Ok(())
}

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
struct Witness {
    merkle_path: Option<(u32, [[u8; 32]; 32])>,
    input_note: orchard::note::Note,
    output_note: orchard::note::Note,
    fvk: FullViewingKey,
    alpha: pasta_curves::Fq,
    rcv: [u8; 32],
    #[pyo3(get)]
    input_index: PyObject,
}

impl Witness {
    fn nf_old(&self) -> Nullifier {
        self.input_note.nullifier(&self.fvk)
    }

    fn rk(&self) -> VerificationKey<SpendAuth> {
        let ak: SpendValidatingKey = self.fvk.clone().into();
        ak.randomize(&self.alpha)
    }
    fn cmx(&self) -> ExtractedNoteCommitment {
        self.output_note.commitment().into()
    }

    fn cv_net(&self) -> ValueCommitment {
        let v_net = self.input_note.value() - self.output_note.value();
        let rcv = ValueCommitTrapdoor::from_bytes(self.rcv).unwrap();
        ValueCommitment::derive(v_net, rcv)
    }
}

#[pymethods]
impl Witness {
    #[staticmethod]
    fn from_msg(py: Python, obj: PyObject) -> PyResult<Self> {
        let input_note = obj.getattr(py, "input_note")?;
        let input_note = Note::from_obj(py, input_note)?.0;
        let output_note = obj.getattr(py, "output_note")?;
        let output_note = Note::from_obj(py, output_note)?.0;
        let fvk: [u8; 96] = obj.getattr(py, "fvk")?.extract(py)?;
        let fvk = orchard::keys::FullViewingKey::from_bytes(&fvk).unwrap();
        let alpha: [u8; 32] = obj.getattr(py, "alpha")?.extract(py)?;
        let alpha = pasta_curves::Fq::from_repr(alpha).unwrap();
        let rcv: [u8; 32] = obj.getattr(py, "rcv")?.extract(py)?;
        let input_index = obj.getattr(py, "input_index")?;
        let merkle_path = if input_index.is_none(py) {
            let mut rng = thread_rng();
            Some((
                rng.next_u32(),
                [(); 32].map(|_| pasta_curves::Fp::random(&mut rng).to_repr()),
            ))
        } else {
            None
        };
        Ok(Witness {
            merkle_path,
            input_note,
            output_note,
            fvk,
            alpha,
            rcv,
            input_index,
        })
        //let rcv = orchard::value::ValueCommitTrapdoor::from_bytes(rcv.clone()).unwrap();
    }
    fn set_merkle_path(&mut self, merkle_path: (u32, [[u8; 32]; 32])) {
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
#[derive(Clone, Debug)]
struct Prover {
    anchor: Anchor,
    enable_spends: bool,
    enable_outputs: bool,
}

fn print_hex(data: &[u8]) {
    for byte in data {
        print!("{:x}", byte);
    }
    println!("");
}

#[pymethods]
impl Prover {
    #[new]
    fn new(anchor: [u8; 32], enable_spends: bool, enable_outputs: bool) -> Self {
        let anchor = Option::from(Anchor::from_bytes(anchor)).expect("invalid anchor");
        Prover {
            anchor,
            enable_spends,
            enable_outputs,
        }
    }

    fn proof(&self, witnesses: Vec<Witness>, pk: &ProvingKey) -> PyResult<Vec<u8>> {
        for w in witnesses.iter() {
            if w.input_note.value().inner() > 0 {
                // Consistency check: all anchors must be equal.
                let cm = w.input_note.commitment();
                let path_root: Anchor = <Option<_>>::from(
                    parse_path(
                        w.merkle_path
                            .ok_or(ProvingError::new_err("Missing merkle path"))?,
                    )
                    .root(cm.into()),
                )
                .ok_or(ProvingError::new_err("Derived from bottom."))?;

                if path_root != self.anchor {
                    return Err(ProvingError::new_err("All anchors must be equal."));
                }
            }

            // Check if note is internal or external.
            let _scope = w
                .fvk
                .clone()
                .scope_for_address(&w.input_note.recipient())
                .ok_or(ProvingError::new_err(
                    "FullViewingKey does not correspond to the given note",
                ))?;
        }
        let instances: Vec<Instance> = witnesses
            .iter()
            .map(|w| {
                Instance::from_parts(
                    self.anchor,
                    w.cv_net(),
                    w.nf_old(),
                    w.rk(),
                    w.cmx(),
                    self.enable_spends,
                    self.enable_outputs,
                )
            })
            .collect();
        for w in witnesses.iter() {
            println!("cv: {:x?}", w.cv_net().to_bytes());
            println!("nf: {:x?}", &w.nf_old().to_bytes());
            println!("rk: {:x?}", <[u8; 32]>::from(w.rk()));
            println!("cmx: {:x?}", &w.cmx().to_bytes());
        }
        println!("{:?}", instances);

        let value_balance = witnesses
            .iter()
            .fold(Some(ValueSum::zero()), |acc, w| {
                acc? + (w.input_note.value() - w.output_note.value())
            })
            .unwrap();

        // Compute the transaction binding signing key.
        let rcvs = witnesses
            .iter()
            .map(|w| ValueCommitTrapdoor::from_bytes(w.rcv.clone()).unwrap())
            .collect::<Vec<ValueCommitTrapdoor>>();

        let bsk = rcvs.iter().sum::<ValueCommitTrapdoor>().into_bsk();

        // Verify that bsk and bvk are consistent.
        let bvk = (witnesses
            .iter()
            .map(|w| w.cv_net())
            .sum::<ValueCommitment>()
            - ValueCommitment::derive(
                value_balance,
                ValueCommitTrapdoor::from_bytes([0u8; 32]).unwrap(),
            ))
        .into_bvk();
        assert_eq!(VerificationKey::from(&bsk), bvk);

        let circuits = witnesses
            .into_iter()
            .map(|w| {
                let rcv = orchard::value::ValueCommitTrapdoor::from_bytes(w.rcv.clone()).unwrap();
                Circuit::from_action_context(
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
        let proof =
            Proof::create(&pk.0, &circuits, &instances, thread_rng()).expect("proving failed");
        Ok(proof.as_ref().into())
    }
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
let value_balance: i64 = witnesses
    .iter()
    .fold(Some(ValueSum::default()), |acc, w| {
        acc? + (w.input_note.value() - w.output_note.value())
    })
    .unwrap()
    .try_into()
    .unwrap();
let value_balance: Amount = value_balance.try_into().unwrap();
*/
//let bsk = witnesses.iter().map(|w| &w.rcv).sum();
//let bsk = redpallas::SigningKey::<Binding>::try_from(bsk).unwrap();
