use ark_bn254::{Bn254 as E, Fr as F};
use ark_groth16::Groth16;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::Result as ArkResult;
use ark_relations::r1cs::ToConstraintField;
use ark_snark::SNARK;
use rand::thread_rng;
use zk_callbacks::generic::interaction::generate_keys_for_statement_in;
use zk_callbacks::generic::interaction::Callback;
use zk_callbacks::generic::interaction::Interaction;
use zk_callbacks::generic::object::Id;
use zk_callbacks::generic::object::Time;
use zk_callbacks::generic::user::{User, UserVar};
use zk_callbacks::impls::centralized::crypto::PlainTikCrypto;
use zk_callbacks::impls::dummy::DummyObjectStore;
use zk_callbacks::impls::hash::Poseidon;
use zk_callbacks::util::UnitVar;
use zk_object::zk_object;

#[zk_object(F)]
#[derive(Default)]
pub struct TestUserData2 {
    pub token1: F,
    pub token2: F,
}

fn int_meth<'a>(tu: &'a User<F, TestUserData2>, _args: F) -> User<F, TestUserData2> {
    tu.clone()
}

fn int_meth_pred<'a>(
    tu_old: &'a UserVar<F, TestUserData2>,
    tu_new: &'a UserVar<F, TestUserData2>,
    _args: FpVar<F>,
) -> ArkResult<()> {
    tu_old
        .data
        .token1
        .enforce_equal(&FpVar::Constant(F::from(1)))?; // enforce a user has a token
    tu_old.data.token1.enforce_equal(&tu_new.data.token1)?;
    Ok(())
}

fn some_pred<'a, 'b>(
    _tu: &'a UserVar<F, TestUserData2>,
    _com: &'b FpVar<F>,
    _args: UnitVar,
) -> ArkResult<()> {
    Ok(())
}

fn cb_meth<'a>(tu: &'a User<F, TestUserData2>, _args: F) -> User<F, TestUserData2> {
    let mut out = tu.clone();
    out.data.token1 = F::from(0); // revoke a token
    out
}

fn cb_pred<'a>(
    tu_old: &'a UserVar<F, TestUserData2>,
    _tu_new: &'a UserVar<F, TestUserData2>,
    _args: FpVar<F>,
) -> ArkResult<()> {
    tu_old
        .data
        .token1
        .enforce_equal(&FpVar::Constant(F::from(0)))?;
    Ok(())
}

fn main() {
    let cb: Callback<F, TestUserData2, F, FpVar<F>> = Callback {
        method_id: Id::from(0),
        expirable: false,
        expiration: Time::from(0),
        method: cb_meth,
        predicate: cb_pred,
    };

    let interaction: Interaction<F, TestUserData2, F, FpVar<F>, 1> = Interaction {
        meth: (int_meth, int_meth_pred),
        callbacks: [cb.clone()],
    };

    let mut rng = thread_rng();

    let _co_store = DummyObjectStore;

    let (pk, vk) = interaction
        .generate_keys::<Poseidon<2>, Groth16<E>, PlainTikCrypto<F>, DummyObjectStore>(&mut rng);

    let (pki, _vki) = generate_keys_for_statement_in::<
        F,
        Poseidon<2>,
        TestUserData2,
        (),
        UnitVar,
        Groth16<E>,
        DummyObjectStore,
    >(some_pred, &mut rng);

    let mut u = User::create(
        TestUserData2 {
            token1: F::from(1),
            token2: F::from(3),
        },
        &mut rng,
    );

    u.prove_statement_and_in::<Poseidon<2>, (), UnitVar, Groth16<E>, DummyObjectStore>(
        &mut rng,
        some_pred,
        &pki,
        ((), ()),
        (),
    )
    .unwrap();

    let exec_method = u
        .interact::<Poseidon<2>, F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, DummyObjectStore, 1>(
            &mut rng,
            interaction.clone(),
            [PlainTikCrypto(F::from(0))],
            ((), ()),
            &pk,
            F::from(0),
        )
        .unwrap();

    let exec_method2 = u
        .interact::<Poseidon<2>, F, FpVar<F>, PlainTikCrypto<F>, Groth16<E>, DummyObjectStore, 1>(
            &mut rng,
            interaction.clone(),
            [PlainTikCrypto(F::from(0))],
            ((), ()),
            &pk,
            F::from(0),
        )
        .unwrap();

    let mut pub_inputs = vec![exec_method.new_object, exec_method.old_nullifier];
    pub_inputs.extend::<Vec<F>>(F::from(0).to_field_elements().unwrap());
    pub_inputs.extend::<Vec<F>>(exec_method.cb_com_list.to_field_elements().unwrap());

    println!(
        "{:?}",
        Groth16::<E>::verify(&vk, &pub_inputs, &exec_method.proof).unwrap()
    );

    println!("{:?}", u);

    let mut pub_inputs = vec![exec_method2.new_object, exec_method2.old_nullifier];
    pub_inputs.extend::<Vec<F>>(F::from(0).to_field_elements().unwrap());
    pub_inputs.extend::<Vec<F>>(exec_method2.cb_com_list.to_field_elements().unwrap());
    pub_inputs.extend::<Vec<F>>(().to_field_elements().unwrap());

    println!(
        "{:?}",
        Groth16::<E>::verify(&vk, &pub_inputs, &exec_method2.proof).unwrap()
    );

    println!("{:?}", u);
}
