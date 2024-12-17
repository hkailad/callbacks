use crate::generic::user::UserData;
use ark_crypto_primitives::sponge::poseidon::{
    find_poseidon_ark_and_mds, PoseidonConfig, PoseidonDefaultConfigEntry,
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::convert::ToConstraintFieldGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::AllocVar;
use ark_r1cs_std::prelude::AllocationMode;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::Field;
use ark_relations::r1cs::Namespace;
use ark_relations::r1cs::SynthesisError;
use core::borrow::Borrow;

// Generates Poseidon params for BLS12-381. This is copied from
//     https://github.com/arkworks-rs/crypto-primitives/blob/54b3ac24b8943fbd984863558c749997e96ff399/src/sponge/poseidon/traits.rs#L69
// and
//     https://github.com/arkworks-rs/crypto-primitives/blob/54b3ac24b8943fbd984863558c749997e96ff399/src/sponge/test.rs
pub(crate) fn gen_poseidon_params<F: PrimeField>(
    rate: usize,
    optimized_for_weights: bool,
) -> PoseidonConfig<F> {
    let params_set = if !optimized_for_weights {
        [
            PoseidonDefaultConfigEntry::new(2, 17, 8, 31, 0),
            PoseidonDefaultConfigEntry::new(3, 5, 8, 56, 0),
            PoseidonDefaultConfigEntry::new(4, 5, 8, 56, 0),
            PoseidonDefaultConfigEntry::new(5, 5, 8, 57, 0),
            PoseidonDefaultConfigEntry::new(6, 5, 8, 57, 0),
            PoseidonDefaultConfigEntry::new(7, 5, 8, 57, 0),
            PoseidonDefaultConfigEntry::new(8, 5, 8, 57, 0),
        ]
    } else {
        [
            PoseidonDefaultConfigEntry::new(2, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(3, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(4, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(5, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(6, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(7, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(8, 257, 8, 13, 0),
        ]
    };

    for param in params_set.iter() {
        if param.rate == rate {
            let (ark, mds) = find_poseidon_ark_and_mds::<F>(
                F::MODULUS_BIT_SIZE as u64,
                rate,
                param.full_rounds as u64,
                param.partial_rounds as u64,
                param.skip_matrices as u64,
            );

            return PoseidonConfig {
                full_rounds: param.full_rounds,
                partial_rounds: param.partial_rounds,
                alpha: param.alpha as u64,
                ark,
                mds,
                rate: param.rate,
                capacity: 1,
            };
        }
    }

    panic!("could not generate poseidon params");
    // F::get_default_poseidon_parameters(rate, optimized_for_weights).unwrap()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitVar(pub ());

impl<F: Field> R1CSVar<F> for UnitVar {
    type Value = UnitVar;

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<F> {
        ConstraintSystemRef::None
    }

    fn value(&self) -> Result<Self::Value, ark_relations::r1cs::SynthesisError> {
        Ok(UnitVar(()))
    }
}

impl<F: Field> AllocVar<(), F> for UnitVar {
    fn new_variable<T: Borrow<()>>(
        _cs: impl Into<Namespace<F>>,
        _f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(UnitVar(()))
    }
}

impl<F: PrimeField + Absorb> UserData<F> for () {
    type UserDataVar = UnitVar;

    fn serialize_elements(&self) -> Vec<crate::generic::object::Ser<F>> {
        vec![F::zero()]
    }

    fn serialize_in_zk(
        _t: Self::UserDataVar,
    ) -> Result<Vec<crate::generic::object::SerVar<F>>, SynthesisError> {
        Ok(vec![FpVar::Constant(F::zero())])
    }
}

impl<F: PrimeField> ToConstraintFieldGadget<F> for UnitVar {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(vec![FpVar::Constant(F::zero())])
    }
}

#[derive(Clone)]
pub struct ArrayVar<T, const N: usize>(pub [T; N]);

impl<F: Field, T: R1CSVar<F>, const N: usize> R1CSVar<F> for ArrayVar<T, N> {
    type Value = [T::Value; N];

    fn cs(&self) -> ConstraintSystemRef<F> {
        let mut result = ConstraintSystemRef::None;
        for var in &self.0 {
            result = var.cs().or(result);
        }
        result
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(core::array::from_fn(|i| self.0[i].value().unwrap()))
    }
}

impl<I, F: Field, A: AllocVar<I, F>, const N: usize> AllocVar<[I; N], F> for ArrayVar<A, N> {
    fn new_variable<T: Borrow<[I; N]>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        Ok(ArrayVar(f().map(|v| {
            let v = v.borrow();
            core::array::from_fn(|i| A::new_variable(cs.clone(), || Ok(&v[i]), mode).unwrap())
        })?))
    }
}
