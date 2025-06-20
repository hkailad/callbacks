use ark_relations::ns;
use std::{borrow::Borrow, marker::PhantomData};

use ark_r1cs_std::{alloc::AllocationMode, select::CondSelectGadget};

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
use ark_relations::r1cs::{Namespace, SynthesisError};
use folding_schemes::frontend::FCircuit;

use crate::{
    crypto::{enc::AECipherSigZK, hash::FieldHash},
    generic::{
        bulletin::PublicCallbackBul,
        object::{Nul, NulVar},
        scan::{PrivScanArgs, PrivScanArgsVar, PubScanArgs, PubScanArgsVar, scan_apply_method_zk},
        user::{User, UserData, UserVar},
    },
};

/// This allows for users to perform a folding scan instead of scanning incremenetally.
///
/// This implements `FCircuit` from PSE's folding-schemes, and so it may be used with any folding
/// scheme supported by FCircuit.
///
/// The parameters passed in include the public arguments for the scan. The private arguments are
/// treated as extra witnesses during the folding process.
///
/// At each folding step, [`PrivScanArgs`] are deserialized from the folding representation. This
/// struct will always have a callback count of `1`, as we only fold the scan one step at a time.
#[derive(Clone)]
pub struct FoldingScan<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone + std::fmt::Debug,
    CBArgsVar: AllocVar<CBArgs, F> + Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    H: FieldHash<F>,
    const NUMCBS: usize,
> {
    _f: PhantomData<F>,
    _u: PhantomData<U>,
    _c: PhantomData<Crypto>,
    _h: PhantomData<H>,
    /// The public arguments during the scan.
    pub const_args: PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>,
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone + std::fmt::Debug,
    CBArgsVar: AllocVar<CBArgs, F> + Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    H: FieldHash<F>,
    const NUMCBS: usize,
> std::fmt::Debug for FoldingScan<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, NUMCBS>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Folding scan")
    }
}

/// An external input to a single folding step. TODO
#[derive(Clone)]
pub struct FoldInput<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone + Default,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + Default,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> where
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
{
    /// The user. TODO
    pub user: User<F, U>,
    /// Scan args. TODO
    pub scan_args: PrivScanArgs<F, CBArgs, Crypto, CBul, NUMCBS>,
    /// New nullifier. TODO
    pub nul: Nul<F>,
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone + Default,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + Default,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> Default for FoldInput<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
where
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
{
    fn default() -> Self {
        Self {
            user: <User<F, U>>::default(),
            scan_args: PrivScanArgs::default(),
            nul: Nul::default(),
        }
    }
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone + Default,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + Default,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> std::fmt::Debug for FoldInput<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
where
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Folding input")
    }
}

/// An external input to a single folding step in-circuit. TODO
#[derive(Clone)]
pub struct FoldInputVar<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> {
    /// The user. TODO
    pub user: UserVar<F, U>,
    /// Scan args. TODO
    pub scan_args: PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMCBS>,
    /// New nullifier. TODO
    pub nul: NulVar<F>,
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone + Default,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + Default,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> std::fmt::Debug for FoldInputVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
where
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Folding input var")
    }
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone + Default,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + Default,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> AllocVar<FoldInput<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>, F>
    for FoldInputVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
where
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
{
    fn new_variable<T: Borrow<FoldInput<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();

        res.and_then(|rec| {
            let rec = rec.borrow();
            let user =
                <UserVar<F, U>>::new_variable(ns!(cs, "user"), || Ok(rec.user.clone()), mode)?;
            let scan_args = PrivScanArgsVar::new_variable(
                ns!(cs, "scan_args"),
                || Ok(rec.scan_args.clone()),
                mode,
            )?;

            let nul = <NulVar<F>>::new_variable(ns!(cs, "nul"), || Ok(rec.nul.clone()), mode)?;
            Ok(Self {
                user,
                scan_args,
                nul,
            })
        })
    }
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone + std::fmt::Debug + Default,
    CBArgsVar: AllocVar<CBArgs, F> + Clone + std::fmt::Debug,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + Default,
    CBul: PublicCallbackBul<F, CBArgs, Crypto> + Clone + std::fmt::Debug + Default,
    H: FieldHash<F>,
    const NUMCBS: usize,
> FCircuit<F> for FoldingScan<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, NUMCBS>
where
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
    U::UserDataVar: CondSelectGadget<F> + EqGadget<F>,
{
    type Params = PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>;

    type ExternalInputs = FoldInput<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>;

    type ExternalInputsVar = FoldInputVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>;

    fn new(init: Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self {
            _f: PhantomData,
            _u: PhantomData,
            _c: PhantomData,
            _h: PhantomData,
            const_args: init,
        })
    }

    fn state_len(&self) -> usize {
        1
    }

    fn generate_step_constraints(
        // this method uses self, so that each FCircuit implementation (and different frontends)
        // can hold a state if needed to store data to generate the constraints.
        &self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<ark_r1cs_std::fields::fp::FpVar<F>>,
        external_inputs: Self::ExternalInputsVar, // inputs that are not part of the state
    ) -> Result<Vec<ark_r1cs_std::fields::fp::FpVar<F>>, ark_relations::r1cs::SynthesisError> {
        User::commit_in_zk::<H>(external_inputs.user.clone())?.enforce_equal(&z_i[0])?;
        let p = PubScanArgsVar::new_constant(cs.clone(), self.const_args.clone())?;
        let mut new_user = scan_apply_method_zk::<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, NUMCBS>(
            &external_inputs.user,
            p,
            external_inputs.scan_args,
        )?;
        new_user.zk_fields.nul = external_inputs.nul;
        Ok(vec![User::commit_in_zk::<H>(new_user)?])
    }
}
