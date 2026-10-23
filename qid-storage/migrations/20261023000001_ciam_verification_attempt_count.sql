ALTER TABLE ciam_verification_challenges
    ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0
    CHECK (attempt_count BETWEEN 0 AND 4294967295);
