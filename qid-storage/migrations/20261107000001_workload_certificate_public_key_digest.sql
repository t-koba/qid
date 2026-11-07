ALTER TABLE workload_certificates
    RENAME COLUMN csr_sha256 TO public_key_sha256;
