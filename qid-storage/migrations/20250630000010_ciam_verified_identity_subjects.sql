-- Only provider-verified links may reserve an external identity.
DROP INDEX idx_ciam_identity_links_external_subject;

CREATE UNIQUE INDEX idx_ciam_identity_links_external_subject
    ON ciam_identity_links (realm_id, provider, external_subject)
    WHERE verified = 1;
