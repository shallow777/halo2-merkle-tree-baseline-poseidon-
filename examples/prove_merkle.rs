use halo2_gadgets::poseidon::{
    primitives::{self as poseidon1, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
    Hash,
};
use halo2_merkle_tree::chips::merkle_v3::MerkleTreeV3Circuit;
use halo2_proofs::{
    circuit::Value,
    pasta::{EqAffine, Fp},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::Instant;

fn compute_merkle_root(leaf: &u64, elements: &Vec<u64>, indices: &Vec<u64>) -> Fp {
    let k = elements.len();
    let mut digest = Fp::from(*leaf);
    let mut message: [Fp; 2];
    for i in 0..k {
        if indices[i] == 0 {
            message = [digest, Fp::from(elements[i])];
        } else {
            message = [Fp::from(elements[i]), digest];
        }
        digest =
            poseidon1::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);
    }
    digest
}

const DEPTH: usize = 256;

fn main() {
    // 1. 准备 Merkle tree 数据
    let leaf = 99u64;

    let mut elements = vec![1u64, 5, 6, 9, 9];
    let mut indices = vec![0u64; 5];

    //elements.resize(DEPTH, 0);
    //indices.resize(DEPTH, 0);
     let mut rng = OsRng;
    elements.resize_with(DEPTH, || rng.next_u64());
    indices.resize_with(DEPTH, || (rng.next_u64() % 2) as u64); // 生成 0 或 1

    
    // 2. 计算 Merkle 根
    let digest = compute_merkle_root(&leaf, &elements, &indices);
    println!("计算出的 Merkle 根：{:?}", digest);

    // 3. 准备电路输入
    let leaf_fp = Value::known(Fp::from(leaf));
    let elements_fp: Vec<Value<Fp>> = elements
        .iter()
        .map(|x| Value::known(Fp::from(*x)))
        .collect();
    let indices_fp: Vec<Value<Fp>> = indices.iter().map(|x| Value::known(Fp::from(*x))).collect();
    
    // 4. 创建电路实例
    let circuit = MerkleTreeV3Circuit {
        leaf: leaf_fp,
        elements: elements_fp,
        indices: indices_fp,
    };

    // 5. 准备公共输入
    // 为每个 instance column 创建数据
    let instance_data_1 = vec![
        Fp::from(leaf),    // row 0: leaf 值
        digest,            // row 1: merkle root 值
    ];
    let instance_data_2 = vec![
        Fp::from(leaf),    // 第二列也需要相同的数据
        digest,  
    ];

    // 构建三层引用结构
    // 1. 最内层: 每列的数据切片
    let instance_slice_1 = &instance_data_1[..];
    let instance_slice_2 = &instance_data_2[..];

    // 2. 中间层: 一个电路的所有列
    let instance_refs = vec![instance_slice_1, instance_slice_2];  // 现在有两列
    let instance_refs = &instance_refs[..];

    // 3. 最外层: 所有电路
    let instances = vec![instance_refs];
    let instances = &instances[..];


    // 6. 初始化参数
    let k = (DEPTH as f64).log2().ceil() as u32 + 8;
    let params: Params<EqAffine> = Params::new(k);

    println!("生成验证密钥...");
    let vk = keygen_vk(&params, &circuit).expect("验证密钥生成失败");
    println!("生成证明密钥...");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("证明密钥生成失败");
    //println!("pk.vk.cs.num_instance_columns: {}", pk.vk.cs.num_instance_columns());
    // 7. 生成证明
    println!("生成证明...");
    let start = Instant::now();
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(&params, &pk, &[circuit], instances, OsRng, &mut transcript)
        .expect("证明生成失败");
    let proof = transcript.finalize();
    let proof_time = start.elapsed();
    println!("生成证明耗时：{:?}", proof_time);

    // 8. 验证证明
    println!("验证证明...");
    let start = Instant::now();
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::init(&proof[..]);
    let result = verify_proof(&params, pk.get_vk(), strategy, instances, &mut transcript);
    let verify_time = start.elapsed();
    println!("验证证明耗时：{:?}", verify_time);

    match result {
        Ok(_) => println!("证明验证成功！"),
        Err(e) => println!("证明验证失败：{:?}", e),
    }
}
