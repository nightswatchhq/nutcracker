//! The Postgres schema, and the one query that matters.
//!
//! Kept as a string constant rather than a migration directory because this crate is a reference
//! implementation: the point is that the shape is legible in one place, not that it ships with a
//! migration runner.

/// DDL. Note what is *absent*: no user column, no namespace name, no plaintext, no embedding.
pub const SCHEMA: &str = r#"
-- Items. Every column is opaque to the provider.
CREATE TABLE IF NOT EXISTS memory_items (
    ns_handle    BYTEA  NOT NULL,          -- 16 bytes; stable across key rotation
    item_id      TEXT   NOT NULL,
    ciphertext   BYTEA  NOT NULL,
    nonce        BYTEA  NOT NULL,          -- 24 bytes, XChaCha20
    wrapped_key  BYTEA  NOT NULL,          -- content key under the namespace key
    wrap_nonce   BYTEA  NOT NULL,
    -- 'blind' | 'plaintext_vectors'. A namespace holding any 'plaintext_vectors' row can no
    -- longer honestly be called end-to-end encrypted, which is why it is per row and not a
    -- namespace-level flag somebody could forget to set.
    index_mode   TEXT   NOT NULL DEFAULT 'blind',
    expires_at   BIGINT,                   -- unix seconds; NULL = keep until forgotten
    created_at   BIGINT NOT NULL,
    PRIMARY KEY (ns_handle, item_id)
);

-- The blind index. One row per (item, band).
CREATE TABLE IF NOT EXISTS memory_buckets (
    ns_handle BYTEA NOT NULL,
    item_id   TEXT  NOT NULL,
    band      INT   NOT NULL,
    token     BYTEA NOT NULL,              -- 16-byte HMAC under the namespace key
    PRIMARY KEY (ns_handle, item_id, band),
    FOREIGN KEY (ns_handle, item_id)
        REFERENCES memory_items (ns_handle, item_id) ON DELETE CASCADE
);

-- Search is a lookup by (namespace, token), so this is the index that matters.
CREATE INDEX IF NOT EXISTS memory_buckets_lookup
    ON memory_buckets (ns_handle, token);

-- GC scans by expiry.
CREATE INDEX IF NOT EXISTS memory_items_expiry
    ON memory_items (expires_at) WHERE expires_at IS NOT NULL;
"#;

/// Candidate lookup: items sharing at least one bucket token with the query, best first.
///
/// `$1` = namespace handle, `$2` = token array, `$3` = limit.
///
/// The tie-break on `item_id` is not decoration. Without it Postgres may return equal-scoring rows
/// in any order it likes, the client's own ranking becomes non-reproducible across identical
/// queries, and debugging a recall complaint becomes guesswork.
pub const SEARCH: &str = r#"
SELECT i.item_id,
       i.ciphertext,
       i.nonce,
       i.wrapped_key,
       i.wrap_nonce,
       COUNT(*) AS shared_bands
  FROM memory_buckets b
  JOIN memory_items   i ON i.ns_handle = b.ns_handle AND i.item_id = b.item_id
 WHERE b.ns_handle = $1
   AND b.token = ANY($2)
   AND (i.expires_at IS NULL OR i.expires_at > EXTRACT(EPOCH FROM NOW()))
 GROUP BY i.item_id, i.ciphertext, i.nonce, i.wrapped_key, i.wrap_nonce
 ORDER BY shared_bands DESC, i.item_id ASC
 LIMIT $3
"#;

/// True when every row in the namespace was written under the blind index.
pub const IS_E2E: &str = r#"
SELECT NOT EXISTS (
    SELECT 1 FROM memory_items
     WHERE ns_handle = $1 AND index_mode <> 'blind'
) AS is_e2e
"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// Column names declared by the schema, so the test below checks structure rather than any
    /// occurrence of a word. `'plaintext_vectors'` appears legitimately as an `index_mode` value,
    /// and a naive substring check flags it — which it did, on the first run.
    fn column_names() -> Vec<String> {
        SCHEMA
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("--"))
            .filter_map(|l| {
                let first = l.split_whitespace().next()?.to_lowercase();
                let structural = [
                    "create",
                    "primary",
                    "foreign",
                    "references",
                    ");",
                    ")",
                    "on",
                    "table",
                    "index",
                ];
                (!structural.contains(&first.as_str())).then_some(first)
            })
            .collect()
    }

    /// The schema must not acquire a column for a user, a namespace name, a plaintext or an
    /// embedding. If somebody adds one, this should be what stops them.
    #[test]
    fn no_column_can_hold_a_user_a_name_or_a_plaintext() {
        let cols = column_names();
        assert!(
            cols.contains(&"ns_handle".to_string()),
            "sanity: the parser found real columns"
        );
        for c in &cols {
            for forbidden in [
                "user",
                "namespace_name",
                "plaintext",
                "embedding",
                "vector",
                "email",
            ] {
                assert!(
                    !c.contains(forbidden),
                    "column `{c}` looks like it holds `{forbidden}`; this store must not"
                );
            }
        }
    }

    #[test]
    fn search_is_scoped_to_a_namespace_and_bounded() {
        assert!(
            SEARCH.contains("b.ns_handle = $1"),
            "never search across namespaces"
        );
        assert!(SEARCH.contains("LIMIT $3"));
        assert!(SEARCH.contains("shared_bands DESC"));
        assert!(
            SEARCH.contains("i.item_id ASC"),
            "ties must break deterministically"
        );
    }

    #[test]
    fn search_excludes_expired_items() {
        assert!(SEARCH.contains("expires_at IS NULL OR i.expires_at >"));
    }

    /// Deleting an item must take its buckets with it, or a forgotten memory keeps showing up as
    /// a candidate id forever.
    #[test]
    fn buckets_cascade_on_delete() {
        assert!(SCHEMA.contains("ON DELETE CASCADE"));
    }
}
