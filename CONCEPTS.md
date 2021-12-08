# Concepts

iotics-identity-go was written in parallel by Tim, Miro & Adrian at Iotics, based on the [iotics-identity-py](https://github.com/Iotic-Labs/iotics-identity-py). It attempts to follow the layout and naming from the python implementation, but certain differences are necessary between the two languages.

All the functionality from iotics-identity-py is available but the package layout is slightly different. Aside from the naming changes snake_case to CamelCase the functions that require several arguments or that have optional arguments are written to accept a struct instead.

These two snippets show the differences in the two implementations using the document builder.

```python
    key_pair_secrets = KeyPairSecrets.build("d2397e8b83cf4a7073a26c1a1cdb6666", "iotics/0/plop/plop", SeedMethod.SEED_METHOD_BIP39, "")
    key_pair = KeyPairSecretsHelper.get_key_pair(key_pair_secrets)
    proof = AdvancedIdentityLocalApi.create_proof(key_pair_secrets, issuer, content=issuer.did.encode())

    doc = RegisterDocumentBuilder() \
        .add_public_key(issuer.name, key_pair.public_base58, revoked=False) \
        .build(issuer.did, purpose, proof.signature, revoked=False)
```

```go
    secret, _  := crypto.NewKeyPairSecrets([]byte("d2397e8b83cf4a7073a26c1a1cdb6666"), "iotics/0/plop/plop", crypto.SeedMethodBip39, "")
    keypair, _  := crypto.GetKeyPair(secret)

    identifier, _ := identity.MakeIdentifier(keypair.PublicKeyBytes)
    issuer, _ := register.NewIssuer(identifier, name)
    newProof, _ := proof.NewProof(keypair.PrivateKey, issuer.Did, issuer.Name, []byte(identifier))

    opts := []register.RegisterDocumentOpts{
        register.AddRootParams(identifier, purpose, newProof.Signature, false),
        register.AddPublicKey(name, keypair.PublicKeyBase58, false),
    }
    registerDocument, _ := register.NewRegisterDocument(opts)
```

## Notable differences

- There is equivalent to the get API client helper functions `get_rest_high_level_identity_api`. In golang the user must construct a resolver client and then the functions on API can be called.
