WITH scope AS (SELECT ? AS realm_id)
SELECT 'realms' AS resource, COUNT(*) AS total FROM realms WHERE id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'users' AS resource, COUNT(*) AS total FROM users WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'credentials_password' AS resource, COUNT(*) AS total FROM credentials_password WHERE user_id = (SELECT realm_id || '-user' FROM scope)
UNION ALL
SELECT 'clients' AS resource, COUNT(*) AS total FROM clients WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'sessions' AS resource, COUNT(*) AS total FROM sessions WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'authorization_codes' AS resource, COUNT(*) AS total FROM authorization_codes WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'token_families' AS resource, COUNT(*) AS total FROM token_families WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'access_tokens' AS resource, COUNT(*) AS total FROM access_tokens WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'credentials_webauthn' AS resource, COUNT(*) AS total FROM credentials_webauthn WHERE user_id = (SELECT realm_id || '-user' FROM scope)
UNION ALL
SELECT 'service_accounts' AS resource, COUNT(*) AS total FROM service_accounts WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'policy_bundles' AS resource, COUNT(*) AS total FROM policy_bundles WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'credentials_totp' AS resource, COUNT(*) AS total FROM credentials_totp WHERE user_id = (SELECT realm_id || '-user' FROM scope)
UNION ALL
SELECT 'vc_credential_statuses' AS resource, COUNT(*) AS total FROM vc_credential_statuses WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'devices' AS resource, COUNT(*) AS total FROM devices WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'par_requests' AS resource, COUNT(*) AS total FROM par_requests WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'device_authorization_grants' AS resource, COUNT(*) AS total FROM device_authorization_grants WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'backchannel_authentication_grants' AS resource, COUNT(*) AS total FROM backchannel_authentication_grants WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'scim_users' AS resource, COUNT(*) AS total FROM scim_users WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'scim_groups' AS resource, COUNT(*) AS total FROM scim_groups WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'scim_devices' AS resource, COUNT(*) AS total FROM scim_devices WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'scim_event_subscriptions' AS resource, COUNT(*) AS total FROM scim_event_subscriptions WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'fedcm_identities' AS resource, COUNT(*) AS total FROM fedcm_identities WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'ciam_consent_grants' AS resource, COUNT(*) AS total FROM ciam_consent_grants WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'ciam_verification_challenges' AS resource, COUNT(*) AS total FROM ciam_verification_challenges WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'ciam_identity_links' AS resource, COUNT(*) AS total FROM ciam_identity_links WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'password_reset_tokens' AS resource, COUNT(*) AS total FROM password_reset_tokens WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'ciam_profiles' AS resource, COUNT(*) AS total FROM ciam_profiles WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'workload_identities' AS resource, COUNT(*) AS total FROM workload_identities WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'workload_certificates' AS resource, COUNT(*) AS total FROM workload_certificates WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'custom_domains' AS resource, COUNT(*) AS total FROM custom_domains WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'ciam_brands' AS resource, COUNT(*) AS total FROM ciam_brands WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'app_catalog_entries' AS resource, COUNT(*) AS total FROM app_catalog_entries WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'ssf_streams' AS resource, COUNT(*) AS total FROM ssf_streams WHERE realm_id = (SELECT realm_id FROM scope)
UNION ALL
SELECT 'ssf_set_replay' AS resource, COUNT(*) AS total FROM ssf_set_replay WHERE realm_id = (SELECT realm_id FROM scope)
