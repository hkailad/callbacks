use crate::generic::asynchr::bulletin::{
    CallbackBulletin, JoinableBulletin, PublicCallbackBul, PublicUserBul, UserBul,
};
use crate::generic::asynchr::service::ServiceProvider;
use crate::generic::bulletin;
use crate::generic::callbacks::CallbackCom;
use crate::generic::object::{Com, ComVar, Nul};
use crate::generic::user::UserData;
use crate::impls::centralized::crypto::{PlainTikCrypto, PlainTikCryptoVar};
use crate::util::UnitVar;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::Compress;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;

pub trait DbHandle {
    type Error;

    #[allow(async_fn_in_trait)]
    async fn insert_updated_object(
        &mut self,
        object: &[u8],
        old_nul: &[u8],
        cb_com_list: &[u8],
        sig: &[u8],
    ) -> Result<(), Self::Error>;

    #[allow(async_fn_in_trait)]
    async fn object_is_in(&self, object: &[u8], old_nul: &[u8], cb_com_list: &[u8]) -> bool;

    #[allow(async_fn_in_trait)]
    async fn has_never_recieved_nul(&self, nul: &[u8]) -> bool;

    type ExternalVerifData;

    #[allow(async_fn_in_trait)]
    async fn verify_new_object(
        &self,
        object: &[u8],
        data: Self::ExternalVerifData,
    ) -> Result<(), Self::Error>;

    #[allow(async_fn_in_trait)]
    async fn insert_interaction_and_tickets(
        &self,
        interaction_id: u64,
        interaction: &[u8],
        internal_tickets: &[Vec<u8>],
    ) -> Result<(), Self::Error>;

    #[allow(async_fn_in_trait)]
    async fn has_never_recieved_tik(&self, tik: &[u8]) -> bool;

    #[allow(async_fn_in_trait)]
    async fn publish_called_ticket(
        &self,
        ticket: &[u8],
        enc_args: &[u8],
    ) -> Result<(), Self::Error>;

    #[allow(async_fn_in_trait)]
    async fn has_ticket_been_called(&self, ticket: &[u8], enc_args: &[u8]) -> bool;
}

pub struct CentralObjectStore<D: DbHandle>(pub D);

impl<F: PrimeField + Absorb, U: UserData<F>, D: DbHandle> PublicUserBul<F, U>
    for CentralObjectStore<D>
{
    type Error = D::Error;

    type MembershipWitness = (); // signature but the entirety of humanity.

    type MembershipWitnessVar = UnitVar;

    type MembershipPub = ();

    type MembershipPubVar = UnitVar;

    async fn verify_in<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _memb_data: Self::MembershipPub,
        _verif_key: &Snark::VerifyingKey,
    ) -> bool {
        let mut object_serial = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::Yes)
            .unwrap();
        let mut old_nul_serial = Vec::new();
        old_nul
            .serialize_with_mode(&mut old_nul_serial, Compress::Yes)
            .unwrap();
        let mut cb_com_list_serial = Vec::new();
        cb_com_list
            .serialize_with_mode(&mut cb_com_list_serial, Compress::Yes)
            .unwrap();
        self.0
            .object_is_in(&object_serial, &old_nul_serial, &cb_com_list_serial)
            .await
    }

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<(), SynthesisError> {
        Ok(()) // CHECK SIGNATURE
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, D: DbHandle> UserBul<F, U> for CentralObjectStore<D> {
    async fn has_never_recieved_nul(&self, nul: &Nul<F>) -> bool {
        let mut nul_serial = Vec::new();
        nul.serialize_with_mode(&mut nul_serial, Compress::Yes)
            .unwrap();
        self.0.has_never_recieved_nul(&nul_serial).await
    }

    async fn append_value<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _memb_data: Self::MembershipPub,
        _verif_key: &Snark::VerifyingKey,
    ) -> Result<(), Self::Error> {
        let mut object_serial = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::Yes)
            .unwrap();
        let mut old_nul_serial = Vec::new();
        old_nul
            .serialize_with_mode(&mut old_nul_serial, Compress::Yes)
            .unwrap();

        let mut cb_com_list_serial = Vec::new();
        cb_com_list
            .serialize_with_mode(&mut cb_com_list_serial, Compress::Yes)
            .unwrap();

        // ADD SIGNING THE OBJECT HERE

        self.0
            .insert_updated_object(&object_serial, &old_nul_serial, &cb_com_list_serial, &[])
            .await
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, D: DbHandle> JoinableBulletin<F, U>
    for CentralObjectStore<D>
{
    type PubData = D::ExternalVerifData;

    async fn join_bul(
        &mut self,
        object: Com<F>,
        pub_data: Self::PubData,
    ) -> Result<(), Self::Error> {
        let mut object_serial = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::Yes)
            .unwrap();
        self.0.verify_new_object(&object_serial, pub_data).await?;

        // Sign object here

        self.0
            .insert_updated_object(&object_serial, &[], &[], &[])
            .await
    }
}

impl<F: PrimeField, D: DbHandle> PublicCallbackBul<F, F, PlainTikCrypto<F>>
    for CentralObjectStore<D>
where
    rand::distributions::Standard: rand::distributions::Distribution<F>,
{
    type Error = D::Error;
    type MembershipPub = ();
    type MembershipPubVar = UnitVar;
    type NonMembershipPub = ();
    type NonMembershipPubVar = UnitVar;
    type MembershipWitness = ();
    type MembershipWitnessVar = UnitVar;
    type NonMembershipWitness = ();
    type NonMembershipWitnessVar = UnitVar;

    async fn verify_in(&self, tik: PlainTikCrypto<F>, enc_args: F) -> bool {
        let mut tik_serial = Vec::new();
        tik.serialize_with_mode(&mut tik_serial, Compress::Yes)
            .unwrap();
        let mut enc_args_serial = Vec::new();
        enc_args
            .serialize_with_mode(&mut enc_args_serial, Compress::Yes)
            .unwrap();
        self.0
            .has_ticket_been_called(&tik_serial, &enc_args_serial)
            .await
    }

    fn enforce_membership_of(
        tikvar: PlainTikCryptoVar<F>,
        extra_witness: Self::MembershipWitness,
        extra_pub: Self::MembershipPub,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }

    fn enforce_nonmembership_of(
        tikvar: PlainTikCryptoVar<F>,
        extra_witness: Self::NonMembershipWitness,
        extra_pub: Self::NonMembershipPub,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

impl<F: PrimeField, D: DbHandle> CallbackBulletin<F, F, PlainTikCrypto<F>> for CentralObjectStore<D>
where
    rand::distributions::Standard: rand::distributions::Distribution<F>,
{
    async fn has_never_recieved_tik(&self, _tik: &PlainTikCrypto<F>) -> bool {
        true
    }

    async fn append_value(
        &mut self,
        tik: PlainTikCrypto<F>,
        enc_args: F,
    ) -> Result<(), Self::Error> {
        let mut tik_serial = Vec::new();
        tik.serialize_with_mode(&mut tik_serial, Compress::Yes)
            .unwrap();
        let mut enc_args_serial = Vec::new();
        enc_args
            .serialize_with_mode(&mut enc_args_serial, Compress::Yes)
            .unwrap();
        self.0
            .publish_called_ticket(&tik_serial, &enc_args_serial)
            .await
    }
}

impl<D: DbHandle> ServiceProvider for CentralObjectStore<D> {
    type InteractionData = u64;
    type Error = D::Error;

    async fn has_never_recieved_tik<
        F: PrimeField + Absorb,
        Args: Clone,
        Crypto: crate::crypto::enc::AECipherSigZK<F, Args>,
    >(
        &self,
        ticket: Crypto::SigPK,
    ) -> bool {
        let mut tik_serial = Vec::new();
        ticket
            .serialize_with_mode(&mut tik_serial, Compress::Yes)
            .unwrap();
        self.0.has_never_recieved_tik(&tik_serial).await
    }

    async fn store_interaction<
        F: PrimeField + Absorb,
        U: UserData<F>,
        Snark: SNARK<F>,
        Args: Clone + ark_ff::ToConstraintField<F>,
        Crypto: crate::crypto::enc::AECipherSigZK<F, Args>,
        const NUMCBS: usize,
    >(
        &self,
        interaction: crate::generic::user::ExecutedMethod<F, Snark, Args, Crypto, NUMCBS>,
        data: u64,
    ) -> Result<(), Self::Error> {
        let mut tickets = Vec::new();
        for i in interaction.cb_tik_list.clone() {
            let mut tik_serial = Vec::new();
            i.0.serialize_with_mode(&mut tik_serial, Compress::Yes)
                .unwrap();
            tickets.push(tik_serial);
        }
        let mut inter_serial = Vec::new();
        interaction
            .serialize_with_mode(&mut inter_serial, Compress::Yes)
            .unwrap();
        self.0
            .insert_interaction_and_tickets(data, &inter_serial, &tickets)
            .await
    }
}

impl<D: DbHandle> CentralObjectStore<D> {
    pub async fn call_ticket<F: PrimeField + Absorb>(
        &mut self,
        internal_ticket: &[u8],
        arguments: F,
    ) -> Result<(), D::Error>
    where
        rand::distributions::Standard: rand::distributions::Distribution<F>,
    {
        let cc = CallbackCom::<F, F, PlainTikCrypto<F>>::deserialize_with_mode(
            internal_ticket,
            Compress::Yes,
            ark_serialize::Validate::No,
        )
        .unwrap();
        let called =
            self.call::<F, F, PlainTikCrypto<F>, Self>(cc, arguments, PlainTikCrypto(F::zero()))?;

        self.verify_call_and_append(called.0, called.1, ())
            .await
            .map_err(|_| "Error verifying and appending.")
            .unwrap();

        Ok(())
    }
}

pub trait NetworkHandle {
    type Error;

    fn object_is_in(&self, object: &[u8], old_nul: &[u8], cb_com_list: &[u8]) -> bool;

    fn has_ticket_been_called(&self, ticket: &[u8], enc_args: &[u8]) -> bool;
}

pub struct CentralNetBulStore<N: NetworkHandle>(pub N);

impl<F: PrimeField + Absorb, U: UserData<F>, N: NetworkHandle> bulletin::PublicUserBul<F, U>
    for CentralNetBulStore<N>
{
    type Error = N::Error;

    type MembershipWitness = (); // signature but the entirety of humanity.

    type MembershipWitnessVar = UnitVar;

    type MembershipPub = ();

    type MembershipPubVar = UnitVar;

    fn verify_in<Args, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _memb_data: Self::MembershipPub,
        _verif_key: &Snark::VerifyingKey,
    ) -> bool {
        let mut object_serial = Vec::new();
        object
            .serialize_with_mode(&mut object_serial, Compress::Yes)
            .unwrap();
        let mut old_nul_serial = Vec::new();
        old_nul
            .serialize_with_mode(&mut old_nul_serial, Compress::Yes)
            .unwrap();
        let mut cb_com_list_serial = Vec::new();
        cb_com_list
            .serialize_with_mode(&mut cb_com_list_serial, Compress::Yes)
            .unwrap();
        self.0
            .object_is_in(&object_serial, &old_nul_serial, &cb_com_list_serial)
    }

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<(), SynthesisError> {
        Ok(()) // CHECK SIGNATURE
    }
}

impl<F: PrimeField, N: NetworkHandle> bulletin::PublicCallbackBul<F, F, PlainTikCrypto<F>>
    for CentralNetBulStore<N>
where
    rand::distributions::Standard: rand::distributions::Distribution<F>,
{
    type Error = N::Error;
    type MembershipPub = ();
    type MembershipPubVar = UnitVar;
    type NonMembershipPub = ();
    type NonMembershipPubVar = UnitVar;
    type MembershipWitness = ();
    type MembershipWitnessVar = UnitVar;
    type NonMembershipWitness = ();
    type NonMembershipWitnessVar = UnitVar;

    fn verify_in(&self, tik: PlainTikCrypto<F>, enc_args: F) -> bool {
        let mut tik_serial = Vec::new();
        tik.serialize_with_mode(&mut tik_serial, Compress::Yes)
            .unwrap();
        let mut enc_args_serial = Vec::new();
        enc_args
            .serialize_with_mode(&mut enc_args_serial, Compress::Yes)
            .unwrap();
        self.0.has_ticket_been_called(&tik_serial, &enc_args_serial)
    }

    fn enforce_membership_of(
        tikvar: PlainTikCryptoVar<F>,
        extra_witness: Self::MembershipWitness,
        extra_pub: Self::MembershipPub,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }

    fn enforce_nonmembership_of(
        tikvar: PlainTikCryptoVar<F>,
        extra_witness: Self::NonMembershipWitness,
        extra_pub: Self::NonMembershipPub,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}
