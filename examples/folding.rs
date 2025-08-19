use ark_bn254::{Bn254 as E, Fr as F, G1Projective as Projective};
use ark_groth16::Groth16;
use ark_grumpkin::Projective as Projective2;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::Result as ArkResult;
use folding_schemes::{
    FoldingScheme,
    commitment::pedersen::Pedersen,
    folding::nova::{Nova, PreprocessorParam, zk::RandomizedIVCProof},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
};
use ark_relations::r1cs::ToConstraintField;
use ark_snark::SNARK;
use rand::thread_rng;
use std::time::SystemTime;
use zk_callbacks::{
    generic::{
        bulletin::{JoinableBulletin, PublicUserBul, UserBul},
        fold::{gen_fold_proof_snark_key, FoldingScan},
        interaction::{Callback, Interaction},
        object::{Id, Time},
        scan::PubScanArgs,
        service::ServiceProvider,
        user::{User, UserVar},
    },
    impls::{
        centralized::{
            crypto::{FakeSigPrivkey, FakeSigPubkey, NoSigOTP},
            ds::sigstore::{
                GRSchnorrCallbackStore, GRSchnorrObjStore, GRSchnorrStore, NonmembStore,
            },
        },
        hash::Poseidon,
    },
};
use zk_object::scannable_zk_object;

#[scannable_zk_object(F)]
#[derive(Default)]
pub struct TestFolding {
    pub token1: F,
    pub token2: F,
}

const NUMSCANS: usize = 1;
type CBArg = F;
type CBArgVar = FpVar<F>;
type U = User<F, TestFolding>;
type UV = UserVar<F, TestFolding>;
type CB = Callback<F, TestFolding, CBArg, CBArgVar>;
type Int1 = Interaction<F, TestFolding, (), (), (), (), CBArg, CBArgVar, 1>;
type PubScan =
    PubScanArgs<F, TestFolding, F, FpVar<F>, NoSigOTP<F>, GRSchnorrCallbackStore<F>, NUMSCANS>;
type OSt = GRSchnorrObjStore;
type CSt = GRSchnorrCallbackStore<F>;
type St = GRSchnorrStore<F>;

fn int_meth<'a>(tu: &'a U, _pub_args: (), _priv_args: ()) -> U {
    let mut a = tu.clone();
    a.data.token1 += F::from(1);

    a
}

fn int_meth_pred<'a>(
    tu_old: &'a UV,
    tu_new: &'a UV,
    _pub_args: (),
    _priv_args: (),
) -> ArkResult<Boolean<F>> {
    let l0 = tu_new.data.token1.is_eq(&FpVar::Constant(F::from(0)))?;
    let l1 = tu_new.data.token1.is_eq(&FpVar::Constant(F::from(1)))?;
    let l2 = tu_new.data.token1.is_eq(&FpVar::Constant(F::from(2)))?;
    let o2 = tu_old.data.token1.clone() + FpVar::Constant(F::from(1));
    let b2 = tu_new.data.token1.is_eq(&o2)?;
    Ok((l0 | l1 | l2) & b2)
}
fn cb_meth<'a>(tu: &'a U, args: F) -> U {
    let mut out = tu.clone();
    out.data.token1 = args;
    out
}

fn cb_pred<'a>(tu_old: &'a UV, args: FpVar<F>) -> ArkResult<UV> {
    let mut tu_new = tu_old.clone();
    tu_new.data.token1 = args;
    Ok(tu_new)
}

fn main() {
    // SERVER SETUP
    let mut rng = thread_rng();

    // create a single callback type
    let cb: CB = Callback {
        method_id: Id::from(0),
        expirable: false,
        expiration: Time::from(300),
        method: cb_meth,
        predicate: cb_pred,
    };

    // irrelevant callback type, we create it to test the checks
    let cb2: CB = Callback {
        method_id: Id::from(1),
        expirable: true,
        expiration: Time::from(1),
        method: cb_meth,
        predicate: cb_pred,
    };

    let mut store = St::new(&mut rng);

    let cb_methods = vec![cb.clone(), cb2.clone()];

    let interaction: Int1 = Interaction {
        meth: (int_meth, int_meth_pred),
        callbacks: [cb.clone()],
    };

    // generate keys for the method described initially
    let (pk, vk) = interaction // see interaction
        .generate_keys::<Poseidon<2>, Groth16<E>, NoSigOTP<F>, OSt>(
            &mut rng,
            Some(store.obj_bul.get_pubkey()),
            (),
            false,
        );

    // generate keys for folding

    // SERVER SIDE

    let (pkf, vkf) = gen_fold_proof_snark_key::<F, Poseidon<2>, TestFolding, Groth16<E>, OSt>(&mut rng, Some(store.obj_bul.get_pubkey()));

    type NF = Nova<
        Projective,
        Projective2,
        FoldingScan<F, TestFolding, CBArg, CBArgVar, NoSigOTP<F>, OSt, CSt, Poseidon<2>, 1>,
        Pedersen<Projective, true>,
        Pedersen<Projective2, true>,
        true,
    >;

    let ps: PubScan = PubScanArgs {
        memb_pub: [store.callback_bul.get_pubkey(); NUMSCANS],
        is_memb_data_const: true,
        nmemb_pub: [store.callback_bul.nmemb_bul.get_pubkey(); NUMSCANS],
        is_nmemb_data_const: true,
        cur_time: store.callback_bul.get_epoch(),
        bulletin: store.callback_bul.clone(),
        cb_methods: cb_methods.clone(),
    };

    let dummy_params = (ps, store.obj_bul.get_pubkey());

    let f_circ: FoldingScan<
        F,
        TestFolding,
        CBArg,
        CBArgVar,
        NoSigOTP<F>,
        OSt,
        CSt,
        Poseidon<2>,
        1,
    > = FoldingScan::new(dummy_params).unwrap();

    let poseidon_config = poseidon_canonical_config::<F>();
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config.clone(), f_circ.clone());
    let nova_params = NF::preprocess(&mut rng, &nova_preprocess_params).unwrap();

    let dummy_folding_scheme: NF =
        NF::init(&nova_params, f_circ, [F::from(0); 2].to_vec()).unwrap();

    let server_params = (
        dummy_folding_scheme.r1cs,
        dummy_folding_scheme.cf_r1cs,
        dummy_folding_scheme.pp_hash,
        poseidon_config,
        nova_params,
    );
    // User

    let mut u = User::create(
        TestFolding {
            token1: F::from(0),
            token2: F::from(3),
        },
        &mut rng,
    );

    let _ = <OSt as JoinableBulletin<F, TestFolding>>::join_bul(
        &mut store.obj_bul,
        u.commit::<Poseidon<2>>(),
        (),
    );

    let exec_method = u
        .exec_method_create_cb::<Poseidon<2>, (), (), (), (), F, FpVar<F>, NoSigOTP<F>, Groth16<E>, OSt, 1>(
            &mut rng,
            interaction.clone(), // see interaction
            [FakeSigPubkey::pk()],
            Time::from(0),
            &store.obj_bul,
            true,
            &pk,
            (),
            (),
        )
        .unwrap();

    let _out = <OSt as UserBul<F, TestFolding>>::verify_interact_and_append::<(), Groth16<E>, 1>(
        &mut store.obj_bul,
        exec_method.new_object.clone(),
        exec_method.old_nullifier.clone(),
        (),
        exec_method.cb_com_list.clone(),
        exec_method.proof.clone(),
        None,
        &vk,
    );
    // Server checks proof on interaction with the verification key, approves it, and stores the new object into the store

    let _ = store
        .approve_interaction_and_store::<TestFolding, Groth16<E>, (), OSt, Poseidon<2>, 1>(
            exec_method,          // output of interaction
            FakeSigPrivkey::sk(), // for authenticity: verify rerandomization of key produces
            // proper tickets (here it doesn't matter)
            (),
            &store.obj_bul.clone(),
            cb_methods.clone(),
            Time::from(0),
            store.obj_bul.get_pubkey(),
            true,
            &vk,
            332, // interaction number
        );

    let exec_method2 = u
        .exec_method_create_cb::<Poseidon<2>, (), (), (), (), F, FpVar<F>, NoSigOTP<F>, Groth16<E>, OSt, 1>(
            &mut rng,
            interaction.clone(),
            [FakeSigPubkey::pk()],
            Time::from(0),
            &store.obj_bul,
            true,
            &pk,
            (),
            (),
        )
        .unwrap();

    let _ = <OSt as UserBul<F, TestFolding>>::verify_interact_and_append::<(), Groth16<E>, 1>(
        &mut store.obj_bul,
        exec_method2.new_object.clone(),
        exec_method2.old_nullifier.clone(),
        (),
        exec_method2.cb_com_list.clone(),
        exec_method2.proof.clone(),
        None,
        &vk,
    );

    // The server approves the interaction and stores it again
    let _ = store
        .approve_interaction_and_store::<TestFolding, Groth16<E>, (), OSt, Poseidon<2>, 1>(
            exec_method2,
            FakeSigPrivkey::sk(),
            (),
            &store.obj_bul.clone(),
            cb_methods.clone(),
            Time::from(0),
            store.obj_bul.get_pubkey(),
            true,
            &vk,
            389,
        );

    // user produces a folding proof

    let start = SystemTime::now();

    let (params, init, v, extra_verif) = u
        .scan_and_create_fold_proof_inputs::<_, _, _, _, _, Poseidon<2>, Groth16<E>, 1>(
            &mut rng,
            <OSt as PublicUserBul<F, TestFolding>>::get_membership_data(
                &store.obj_bul,
                u.commit::<Poseidon<2>>(),
            )
            .unwrap(),
            &store.callback_bul,
            true,
            (true, true),
            store.callback_bul.nmemb_bul.get_epoch(),
            cb_methods.clone(),
            &pkf,
            2,
        );


    println!("Rerandomization time: {:?}", start.elapsed().unwrap());

    let f_circ: FoldingScan<
        F,
        TestFolding,
        CBArg,
        CBArgVar,
        NoSigOTP<F>,
        OSt,
        CSt,
        Poseidon<2>,
        1,
    > = FoldingScan::new(params).unwrap();

    let mut folding_scheme: NF = NF::init(&server_params.4, f_circ, init.clone()).unwrap();

    let start = SystemTime::now();

    folding_scheme
        .prove_step(&mut rng, v[0].clone(), None)
        .unwrap();

    println!("Fold step time: {:?}", start.elapsed().unwrap());

    let start = SystemTime::now();

    folding_scheme
        .prove_step(&mut rng, v[1].clone(), None)
        .unwrap();

    println!("Fold step time: {:?}", start.elapsed().unwrap());

    // let start = SystemTime::now();

    // folding_scheme
    //     .prove_step(
    //         &mut rng,
    //         [u.to_fold_repr(), prs2.to_fold_repr()].concat(),
    //         None,
    //     )
    //     .unwrap();

    // println!("Fold step time: {:?}", start.elapsed().unwrap());

    let start = SystemTime::now();

    let proof = RandomizedIVCProof::new(&folding_scheme, &mut rng).unwrap();

    let client_proof_data = (
        folding_scheme.i.clone(),
        folding_scheme.z_0.clone(),
        folding_scheme.z_i.clone(),
        proof,
        extra_verif
    );

    println!("Blinding step time: {:?}", start.elapsed().unwrap());

    // Server now verifies folding proof.

    let verify =
        RandomizedIVCProof::verify::<Pedersen<Projective, true>, Pedersen<Projective2, true>>(
            &server_params.0,
            &server_params.1,
            server_params.2.clone(),
            &server_params.3,
            client_proof_data.0.clone(),
            client_proof_data.1.clone(),
            client_proof_data.2.clone(),
            &client_proof_data.3,
        ).is_ok();

    let verif2 = client_proof_data.1[0] == client_proof_data.4.0
        && client_proof_data.1[1] == store.callback_bul.get_epoch();


    let mut pub_inputs = vec![];
    pub_inputs.extend::<Vec<F>>([client_proof_data.4.0, client_proof_data.4.1].to_field_elements().unwrap()); // pub args
    // pub_inputs.extend::<Vec<F>>(store.obj_bul.get_pubkey().to_field_elements().unwrap()); // pub membership data (if not constant)
    // The public membership data in this case is constant, so we don't need to pass it in as an
    // argument
    let verif3 = Groth16::<E>::verify(&vkf, &pub_inputs, &client_proof_data.4.2).unwrap_or(false);

    println!("{:?}", verify);
    println!("{:?}", verif2);
    println!("{:?}", verif3);

    println!("User at the end : {:?}", u);
    println!(
        "Committed user at the end : {:?}",
        u.commit::<Poseidon<2>>()
    );
}
