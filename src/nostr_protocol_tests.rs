#[cfg(test)]
mod tests {
    use crate::nostr_protocol::*;
    use nostr_sdk::prelude::*;

    #[test]
    fn test_transfer_id_generation() {
        let id1 = generate_transfer_id();
        let id2 = generate_transfer_id();

        // Should be 32 hex characters (16 bytes)
        assert_eq!(id1.len(), 32);
        assert_eq!(id2.len(), 32);

        // Should be different
        assert_ne!(id1, id2);

        // Should be valid hex
        assert!(hex::decode(&id1).is_ok());
        assert!(hex::decode(&id2).is_ok());
    }

    #[test]
    fn test_ready_event_creation() {
        let receiver_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let transfer_id = generate_transfer_id();

        // Create ready event
        let event =
            create_ready_event(&receiver_keys, &sender_keys.public_key(), &transfer_id).unwrap();

        // Verify event properties
        assert_eq!(event.kind, nostr_file_transfer_kind());
        assert_eq!(event.pubkey, receiver_keys.public_key());
        assert!(is_ready_event(&event));
        assert!(!is_tmpfile_url_event(&event));
        assert!(!is_completion_event(&event));

        // Verify transfer ID
        assert_eq!(get_transfer_id(&event).unwrap(), transfer_id);
    }

    #[test]
    fn test_tmpfile_url_event_creation_and_parsing() {
        let sender_keys = Keys::generate();
        let receiver_keys = Keys::generate();
        let transfer_id = generate_transfer_id();
        let download_url = "https://tmpfiles.org/dl/12345/test.dat";

        // Create tmpfile URL event
        let event = create_tmpfile_url_event(
            &sender_keys,
            &receiver_keys.public_key(),
            &transfer_id,
            download_url,
        )
        .unwrap();

        // Verify event properties
        assert_eq!(event.kind, nostr_file_transfer_kind());
        assert_eq!(event.pubkey, sender_keys.public_key());
        assert!(is_tmpfile_url_event(&event));
        assert!(!is_ready_event(&event));
        assert!(!is_completion_event(&event));

        // Parse and verify
        let parsed_url = parse_tmpfile_url_event(&event).unwrap();
        assert_eq!(parsed_url, download_url);

        // Verify transfer ID
        assert_eq!(get_transfer_id(&event).unwrap(), transfer_id);
    }

    #[test]
    fn test_completion_event_creation() {
        let receiver_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let transfer_id = generate_transfer_id();

        // Create completion event
        let event =
            create_completion_event(&receiver_keys, &sender_keys.public_key(), &transfer_id)
                .unwrap();

        // Verify event properties
        assert_eq!(event.kind, nostr_file_transfer_kind());
        assert_eq!(event.pubkey, receiver_keys.public_key());
        assert!(is_completion_event(&event));
        assert!(!is_ready_event(&event));
        assert!(!is_tmpfile_url_event(&event));

        // Verify transfer ID
        assert_eq!(get_transfer_id(&event).unwrap(), transfer_id);
    }
}
