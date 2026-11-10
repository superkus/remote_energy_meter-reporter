mod support;

use remote_energy_meter_reporter::protocol_v1::{
    ErrorClass,
    sas::{SasWordLists, derive_interactive_sas, parse_sas, render_sas, verify_sas},
};
use support::{fixture, hex_decode, named_value, parse_json, vector_case};

const KNOWN_BYTES: [u8; 6] = [0x4d, 0xf1, 0x04, 0xcf, 0xb9, 0xf9];
const KNOWN_PHRASE: &str = "dreadful vacancy adrift Saturday sentence Waterloo";

fn with_word_lists<T>(operation: impl FnOnce(&SasWordLists<'_>) -> T) -> T {
    let even = fixture("pgp-word-list/even.txt");
    let odd = fixture("pgp-word-list/odd.txt");
    let lists = SasWordLists::load(&even, &odd).expect("pinned word lists must load");
    operation(&lists)
}

fn invalid<T: std::fmt::Debug>(result: Result<T, ErrorClass>) {
    assert_eq!(result.unwrap_err(), ErrorClass::InvalidRequest);
}

fn unauthenticated<T: std::fmt::Debug>(result: Result<T, ErrorClass>) {
    assert_eq!(result.unwrap_err(), ErrorClass::AuthenticationRequired);
}

#[test]
fn word_lists_are_exact_complete_ascii_ordered_unique_and_hash_pinned() {
    let even = fixture("pgp-word-list/even.txt");
    let odd = fixture("pgp-word-list/odd.txt");
    for (raw, expected_hash) in [
        (
            even.as_slice(),
            "37a65f88512467edd12a1ab3eeb5f4328230e86711a8efde6333361ce10f4fcf",
        ),
        (
            odd.as_slice(),
            "c2f23c2233d4d7291107e8f796c374d0cb1fb30c1391bcb4f6480243de8ebf5a",
        ),
    ] {
        assert_eq!(support::hex_encode(&support::sha256(raw)), expected_hash);
        assert!(raw.is_ascii());
        assert!(raw.ends_with(b"\n"));
        assert!(!raw.ends_with(b"\n\n"));
        assert!(!raw.contains(&b'\r'));
        let text = std::str::from_utf8(raw).unwrap();
        let words: Vec<_> = text.strip_suffix('\n').unwrap().split('\n').collect();
        assert_eq!(words.len(), 256);
        assert_eq!(
            words
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            256
        );
        assert!(words.iter().all(|word| {
            !word.is_empty()
                && word.bytes().all(|byte| byte.is_ascii_alphabetic())
                && *word == word.trim()
        }));
    }

    with_word_lists(|lists| {
        assert_eq!(
            render_sas(lists, &[0x00, 0x00, 0x09, 0x0a, 0xff, 0xff]).unwrap(),
            "aardvark adroitness Algol Apollo Zulu Yucatan"
        );
    });
}

#[test]
fn word_list_loader_rejects_any_non_pinned_or_malformed_resource() {
    let even = fixture("pgp-word-list/even.txt");
    let odd = fixture("pgp-word-list/odd.txt");
    assert!(SasWordLists::load(&even, &odd).is_ok());

    let mut altered_even = even.clone();
    altered_even[0] ^= 1;
    invalid(SasWordLists::load(&altered_even, &odd));
    let mut altered_odd = odd.clone();
    let altered_index = altered_odd.len() - 2;
    altered_odd[altered_index] ^= 1;
    invalid(SasWordLists::load(&even, &altered_odd));
    invalid(SasWordLists::load(&even[..even.len() - 1], &odd));
    invalid(SasWordLists::load(&even, &odd[..odd.len() - 1]));
}

#[test]
fn known_pgp_examples_preserve_parity_case_and_order() {
    with_word_lists(|lists| {
        assert_eq!(
            render_sas(lists, &hex_decode("e58200000000")).unwrap(),
            "topmost Istanbul aardvark adroitness aardvark adroitness"
        );
        assert_eq!(
            render_sas(lists, &hex_decode("82e500000000")).unwrap(),
            "miser travesty aardvark adroitness aardvark adroitness"
        );
    });
}

#[test]
fn every_index_in_all_six_positions_uses_the_exact_alternating_list() {
    let even = fixture("pgp-word-list/even.txt");
    let odd = fixture("pgp-word-list/odd.txt");
    let expected_tables: Vec<Vec<&str>> = [&even, &odd]
        .into_iter()
        .map(|raw| {
            std::str::from_utf8(raw)
                .unwrap()
                .strip_suffix('\n')
                .unwrap()
                .split('\n')
                .collect()
        })
        .collect();
    let lists = SasWordLists::load(&even, &odd).unwrap();

    for position in 0..6 {
        let mut seen = std::collections::BTreeSet::new();
        for index in 0_u16..=255 {
            let mut value = [0_u8; 6];
            value[position] = index as u8;
            let phrase = render_sas(&lists, &value).unwrap();
            let words: Vec<_> = phrase.split(' ').collect();
            assert_eq!(words.len(), 6);
            assert_eq!(phrase.matches(' ').count(), 5);
            assert!(phrase.is_ascii());
            assert!(phrase.len() <= 65);
            assert_eq!(
                words[position],
                expected_tables[position % 2][usize::from(index)]
            );
            assert_eq!(parse_sas(&lists, &phrase).unwrap(), value);
            seen.insert(words[position].to_owned());
        }
        assert_eq!(seen.len(), 256);
    }
}

#[test]
fn merged_interactive_vector_derives_and_renders_exactly() {
    let vectors = parse_json(&fixture("vectors/interactive-enrollment.json"));
    let case = vector_case(&vectors, "interactive.sas");
    let transcript = hex_decode(named_value(case, "intermediates", "transcript"));
    let reporter_nonce = hex_decode(named_value(case, "inputs", "transcript.reporter_nonce"));
    let core_nonce = hex_decode(named_value(case, "inputs", "transcript.core_nonce"));

    assert_eq!(transcript.len(), 722);
    let derived = derive_interactive_sas(&transcript, &reporter_nonce, &core_nonce).unwrap();
    assert_eq!(derived, KNOWN_BYTES);
    with_word_lists(|lists| {
        assert_eq!(render_sas(lists, &derived).unwrap(), KNOWN_PHRASE);
        assert_eq!(parse_sas(lists, KNOWN_PHRASE).unwrap(), derived);
        assert_eq!(verify_sas(lists, &derived, KNOWN_PHRASE), Ok(()));
    });
}

#[test]
fn derivation_fixes_digest_nonce_order_info_length_and_boundaries() {
    let transcript = b"REM-TRANSCRIPT\x01test transcript bytes";
    let reporter_nonce: Vec<u8> = (0..32).collect();
    let core_nonce: Vec<u8> = (32..64).collect();
    let expected = hex_decode("6f5a168aa07c");

    assert_eq!(
        derive_interactive_sas(transcript, &reporter_nonce, &core_nonce).unwrap(),
        expected.as_slice()
    );
    assert_ne!(
        derive_interactive_sas(transcript, &core_nonce, &reporter_nonce).unwrap(),
        expected.as_slice()
    );
    assert_ne!(
        derive_interactive_sas(
            b"REM-TRANSCRIPT\x01test transcript bytes!",
            &reporter_nonce,
            &core_nonce,
        )
        .unwrap(),
        expected.as_slice()
    );

    assert!(derive_interactive_sas(b"x", &[0; 32], &[0; 32]).is_ok());
    assert!(derive_interactive_sas(&vec![b'x'; 4096], &[0; 32], &[0; 32]).is_ok());
    for transcript in [Vec::new(), vec![b'x'; 4097]] {
        invalid(derive_interactive_sas(&transcript, &[0; 32], &[0; 32]));
    }
    for length in [31, 33] {
        invalid(derive_interactive_sas(b"x", &vec![0; length], &[0; 32]));
        invalid(derive_interactive_sas(b"x", &[0; 32], &vec![0; length]));
    }
}

#[test]
fn render_rejects_every_non_six_byte_value_and_uses_exact_spaces() {
    with_word_lists(|lists| {
        for length in [0, 1, 5, 7, 4096] {
            invalid(render_sas(lists, &vec![0; length]));
        }
        let phrase = render_sas(lists, &KNOWN_BYTES).unwrap();
        assert_eq!(phrase, KNOWN_PHRASE);
        assert_eq!(phrase.matches(' ').count(), 5);
        assert_eq!(phrase, phrase.split(' ').collect::<Vec<_>>().join(" "));
    });
}

#[test]
fn parser_rejects_word_count_list_case_punctuation_unicode_and_spacing_mutations() {
    with_word_lists(|lists| {
        for phrase in [
            "dreadful",
            "disruptive vacancy adrift Saturday sentence Waterloo",
            "dreadful unwind adrift Saturday sentence Waterloo",
            "Dreadful vacancy adrift Saturday sentence Waterloo",
            "dreadful vacancy adrift Saturday sentence Waterloo!",
            "dreadful vacancy adrift Saturday sentence Yucatán",
            " dreadful vacancy adrift Saturday sentence Waterloo",
            "dreadful vacancy adrift Saturday sentence Waterloo ",
            "dreadful  vacancy adrift Saturday sentence Waterloo",
            "dreadful\tvacancy adrift Saturday sentence Waterloo",
            "dreadful\nvacancy adrift Saturday sentence Waterloo",
        ] {
            invalid(parse_sas(lists, phrase));
        }
        invalid(parse_sas(lists, &"x".repeat(66)));
    });
}

#[test]
fn verifier_rejects_one_valid_word_index_mutation_in_each_position() {
    with_word_lists(|lists| {
        for phrase in [
            "drifter vacancy adrift Saturday sentence Waterloo",
            "dreadful adviser adrift Saturday sentence Waterloo",
            "dreadful vacancy adult Saturday sentence Waterloo",
            "dreadful vacancy adrift savagery sentence Waterloo",
            "dreadful vacancy adrift Saturday shadow Waterloo",
            "dreadful vacancy adrift Saturday sentence Wichita",
        ] {
            unauthenticated(verify_sas(lists, &KNOWN_BYTES, phrase));
        }
        for length in [0, 5, 7] {
            invalid(verify_sas(lists, &vec![0; length], KNOWN_PHRASE));
        }
    });
}
