#![cfg(feature = "std")]
#![allow(unused)]

use alloc::vec;
use sha2::Sha512;

use crate::{KeyHash, Sha512Jmt, mock::MockTreeStore};

use super::vectors::{KeyValuePair, TestVector};

const DESCRIPTION: &str = "Test vectors for a JMT instantiated with the sha2-512 hash function. Keys and values are hex-encoded byte strings. Neither keys nor values have been pre-hashed.";

fn test_vector_from_pairs(pairs: Vec<KeyValuePair>) -> TestVector {
    let store = MockTreeStore::default();
    let tree = Sha512Jmt::new(&store);
    let key_value_pairs = pairs
        .iter()
        .map(|pair| (KeyHash::with::<Sha512>(&pair.key), Some(pair.value.clone())))
        .collect::<Vec<_>>();
    let (root, _batch) = tree.put_value_set(key_value_pairs, 0).unwrap();
    TestVector {
        expected_root: root.0,
        data: pairs,
    }
}

fn create_vector_for_empty_trie() -> TestVector {
    test_vector_from_pairs(vec![])
}

fn compute_vector_with_one_leaf() -> TestVector {
    test_vector_from_pairs(vec![KeyValuePair {
        key: b"hello".to_vec(),
        value: b"world".to_vec(),
    }])
}

fn compute_vector_with_two_leaves() -> TestVector {
    test_vector_from_pairs(vec![
        KeyValuePair {
            key: b"hello".to_vec(),
            value: b"world".to_vec(),
        },
        KeyValuePair {
            key: b"goodbye".to_vec(),
            value: b"world".to_vec(),
        },
    ])
}

#[test]
#[ignore]
fn generate_vectors() {
    use super::vectors::TestVectorWrapper;

    let vectors = vec![
        create_vector_for_empty_trie(),
        compute_vector_with_one_leaf(),
        compute_vector_with_two_leaves(),
    ];

    let test_vectors = TestVectorWrapper {
        description: DESCRIPTION.to_string(),
        hash_function: "sha2_512".to_string(),
        vectors,
    };
    let file = std::fs::File::create("sha2_512_vectors.json").unwrap();
    let writer = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &test_vectors).unwrap();
}
