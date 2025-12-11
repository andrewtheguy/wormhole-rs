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
    fn test_chunk_event_creation_and_parsing() {
        let sender_keys = Keys::generate();
        let transfer_id = generate_transfer_id();
        let encrypted_data = b"test_encrypted_chunk_data";

        // Create chunk event
        let event = create_chunk_event(
            &sender_keys,
            &transfer_id,
            5,
            10,
            encrypted_data,
        )
        .unwrap();

        // Verify event properties
        assert_eq!(event.kind, nostr_file_transfer_kind());
        assert_eq!(event.pubkey, sender_keys.public_key());
        assert!(is_chunk_event(&event));
        assert!(!is_ack_event(&event));

        // Parse and verify
        let (seq, total, parsed_data) = parse_chunk_event(&event).unwrap();
        assert_eq!(seq, 5);
        assert_eq!(total, 10);
        assert_eq!(parsed_data, encrypted_data);

        // Verify transfer ID
        assert_eq!(get_transfer_id(&event).unwrap(), transfer_id);
    }

    #[test]
    fn test_ack_event_creation_and_parsing() {
        let receiver_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let transfer_id = generate_transfer_id();

        // Create ACK event
        let event =
            create_ack_event(&receiver_keys, &sender_keys.public_key(), &transfer_id, 5).unwrap();

        // Verify event properties
        assert_eq!(event.kind, nostr_file_transfer_kind());
        assert_eq!(event.pubkey, receiver_keys.public_key());
        assert!(is_ack_event(&event));
        assert!(!is_chunk_event(&event));

        // Parse and verify
        let seq = parse_ack_event(&event).unwrap();
        assert_eq!(seq, 5);

        // Verify transfer ID
        assert_eq!(get_transfer_id(&event).unwrap(), transfer_id);
    }

    #[test]
    fn test_final_ack() {
        let receiver_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let transfer_id = generate_transfer_id();

        // Create final ACK with seq = -1
        let event =
            create_ack_event(&receiver_keys, &sender_keys.public_key(), &transfer_id, -1).unwrap();

        let seq = parse_ack_event(&event).unwrap();
        assert_eq!(seq, -1);
    }
}
