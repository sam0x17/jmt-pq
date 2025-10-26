// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use alloc::{format, vec};

use anyhow::Result;
use rand::{Rng, SeedableRng, rngs::StdRng};
use sha2::Sha512;
#[cfg(feature = "std")]
use std::thread;

use super::helper::plus_one;
use crate::{
    HASH_SIZE, KeyHash, OwnedValue, Sha512Jmt, iterator::JellyfishMerkleIterator,
    mock::MockTreeStore, types::Version,
};

#[test]
fn test_iterator_same_version() {
    for i in (1..100).step_by(11) {
        test_n_leaves_same_version(i);
    }
}

#[test]
fn test_iterator_multiple_versions() {
    test_n_leaves_multiple_versions(50);
}

#[test]
fn test_long_path() {
    #[cfg(feature = "std")]
    {
        thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| test_n_consecutive_addresses(50))
            .expect("spawn iterator long-path thread")
            .join()
            .expect("long-path test panicked");
    }
    #[cfg(not(feature = "std"))]
    {
        test_n_consecutive_addresses(50);
    }
}

fn test_n_leaves_same_version(n: usize) {
    let db = Arc::new(MockTreeStore::default());
    let tree = Sha512Jmt::new(&*db);

    let mut rng = StdRng::from_seed([1; 32]);

    let mut btree = BTreeMap::new();
    for i in 0..n {
        let mut key = [0u8; HASH_SIZE];
        rng.fill(&mut key);
        let key = KeyHash(key);
        let value = i.to_be_bytes().to_vec();
        assert_eq!(btree.insert(key, value), None);
    }

    let (_root_hash, batch) = tree
        .put_value_set(
            btree.iter().map(|(k, v)| (*k, Some(v.clone()))),
            0, /* version */
        )
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();

    let btree = btree.into_iter().collect::<BTreeMap<KeyHash, OwnedValue>>();

    run_tests(db, &btree, 0 /* version */);
}

fn test_n_leaves_multiple_versions(n: usize) {
    let db = Arc::new(MockTreeStore::default());
    let tree = Sha512Jmt::new(&*db);

    let mut btree = BTreeMap::new();
    for i in 0..n {
        let key = KeyHash::with::<Sha512>(format!("key{}", i));
        let value = i.to_be_bytes().to_vec();
        assert_eq!(btree.insert(key, value.clone()), None);
        let (_root_hash, batch) = tree
            .put_value_set(vec![(key, Some(value))], i as Version)
            .unwrap();
        db.write_tree_update_batch(batch).unwrap();
        run_tests(Arc::clone(&db), &btree, i as Version);
    }
}

fn test_n_consecutive_addresses(n: usize) {
    let db = Arc::new(MockTreeStore::default());
    let tree = Sha512Jmt::new(&*db);

    let btree: BTreeMap<_, _> = (0..n)
        .map(|i| {
            let mut buf = [0u8; HASH_SIZE];
            buf[HASH_SIZE - 8..].copy_from_slice(&(i as u64).to_be_bytes());
            (KeyHash(buf), i.to_be_bytes().to_vec())
        })
        .collect();

    let (_root_hash, batch) = tree
        .put_value_set(
            btree.iter().map(|(k, v)| (*k, Some(v.clone()))),
            0, /* version */
        )
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();

    run_tests(db, &btree, 0 /* version */);
}

fn run_tests(db: Arc<MockTreeStore>, btree: &BTreeMap<KeyHash, OwnedValue>, version: Version) {
    {
        let iter =
            JellyfishMerkleIterator::new(Arc::clone(&db), version, KeyHash([0u8; HASH_SIZE]))
                .unwrap();
        assert_eq!(
            iter.collect::<Result<Vec<_>>>().unwrap(),
            btree.clone().into_iter().collect::<Vec<_>>(),
        );
    }

    for i in 0..btree.len() {
        {
            let iter = JellyfishMerkleIterator::new_by_index(Arc::clone(&db), version, i).unwrap();
            assert_eq!(
                iter.collect::<Result<Vec<_>>>().unwrap(),
                btree.clone().into_iter().skip(i).collect::<Vec<_>>(),
            );
        }

        let ith_key = *btree.keys().nth(i).unwrap();

        {
            let iter = JellyfishMerkleIterator::new(Arc::clone(&db), version, ith_key).unwrap();
            assert_eq!(
                iter.collect::<Result<Vec<_>>>().unwrap(),
                btree.clone().into_iter().skip(i).collect::<Vec<_>>(),
            );
        }

        {
            let ith_key_plus_one = plus_one(ith_key);
            let iter =
                JellyfishMerkleIterator::new(Arc::clone(&db), version, ith_key_plus_one).unwrap();
            assert_eq!(
                iter.collect::<Result<Vec<_>>>().unwrap(),
                btree.clone().into_iter().skip(i + 1).collect::<Vec<_>>(),
            );
        }
    }

    {
        let iter =
            JellyfishMerkleIterator::new_by_index(Arc::clone(&db), version, btree.len()).unwrap();
        assert_eq!(iter.collect::<Result<Vec<_>>>().unwrap(), vec![]);
    }

    {
        let iter =
            JellyfishMerkleIterator::new(Arc::clone(&db), version, KeyHash([0xFF; HASH_SIZE]))
                .unwrap();
        assert_eq!(iter.collect::<Result<Vec<_>>>().unwrap(), vec![]);
    }
}
