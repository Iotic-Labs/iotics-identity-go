Feature: Advanced Identity API

Background:
    Given a resolver exists

  @advanced_api @done
  Scenario: Get a register document from a registered identity
    Given a registered identity with name "#ARegIdentity1"
    When I get the associated document
    Then The registered identity issuer did is equal to the document did

  @advanced_api
  Scenario: Register identity owning the document is in the document public key
    Given a registered identity with name "#ARegIdentityOwningDoc1"
    When I get the associated document
    Then The register document has the registered identity public key

  @advanced_api
  Scenario: Register identity owning the document is allowed for control and authentication
    Given a registered identity with name "#ARegIdentityOwningDoc1"
    When I check if the registered identity is allowed for control and authentication on the associated document
    Then the registered identity is allowed

  @advanced_api
  Scenario: Several registered identity can belong to the same document
    Given a register document with several owners
    When I get the associated document
    Then The register document has several public keys

  @advanced_api
  Scenario: Add a register document owner
    Given a registered identity with name "#OwnerForNewOwner"
    And a new twin "#NewOwner" public key
    When I add the new owner to the document
    Then the new owner is allowed for authentication and control on the document

  @advanced_api
  Scenario: Remove a register document owner
    Given a registered identity with name "#InitialOwner"
    And a another twin "#OtherExistingOwner" owner
    When I remove the other owner from the document
    Then the removed owner is not allowed for authentication or control on the document

  @advanced_api
  Scenario: Revoke a register document owner
    Given a registered identity with name "#InitialOwner"
    And a another twin "#OtherExistingOwner" owner
    When I revoke the other owner key
    Then the revoked owner is not allowed for authentication or control on the document

  @advanced_api
  Scenario: Add an authentication key to a register document
    Given a registered identity with name "#OwnerForNewAuth"
    And a new twin "#NewAuthKey" public key
    When I add the new authentication key to the document
    Then the authentication key owner is allowed for authentication on the document

  @advanced_api
  Scenario: Remove an authentication key from a register document
    Given a registered identity with name "#OwnerForNewAuth"
    And a another twin "#ExistingAuthKey" authentication public key
    When I remove the authentication key from the document
    Then the removed authentication key owner is not allowed for authentication on the document

  @advanced_api
  Scenario: Revoke an authentication key
    Given a registered identity with name "#OwnerForNewAuth"
    And a another twin "#ExistingAuthKey" authentication public key
    When I revoke the authentication key from the document
    Then the revoked authentication key owner is not allowed for authentication on the document

  @advanced_api
  Scenario: Add a control delegation between 2 existing registered identities
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB"
    When one identity delegates control to another with delegation name "#NewDelegation"
    Then the other identity is allowed for control on the initial identity document

  @advanced_api
  Scenario: Add a control delegation proof (from an other registered identity) to a document
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB"
    And a delegation proof for document of "#IDA" created by "#IDB"
    When I add the control delegation proof "#DelegFromProof" to the document
    Then the delegated registered identity is allowed for control on the document

  @advanced_api
  Scenario: Add a generic control delegation proof to a document
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB"
    And a generic delegation proof created by "#IDB"
    When I add the generic control delegation proof "#DelegFromProof" to the document
    Then the delegated registered identity is allowed for control on the document

  @advanced_api
  Scenario: Remove a control delegation proof from a register document
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB"
    And a delegation proof for document of "#IDA" created by "#IDB"
    And I add the control delegation proof "#DelegFromProof" to the document
    When I remove the control delegation proof from the document
    Then the delegated registered identity is not allowed for control on the document after delegation remove

  @advanced_api
  Scenario: Revoke a control delegation proof
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB"
    And a delegation proof for document of "#IDA" created by "#IDB"
    And I add the control delegation proof "#DelegFromProof" to the document
    When I revoke the control delegation proof
    Then the delegated registered identity is not allowed for control on the document after delegation revoke

  @advanced_api
  Scenario: Add an authentication delegation between 2 existing registered identities
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB"
    When one identity delegates authentication to another with delegation name "#NewDelegation"
    Then the other identity is allowed for authentication on the initial identity document

  @advanced_api
  Scenario: Add an authentication delegation proof (from an other registered identity) to a document
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB"
    And a delegation proof for document of "#IDA" created by "#IDB"
    When I add the authentication delegation proof "#DelegFromProof" to the document
    Then the other identity is allowed for authentication on the initial identity document

  @advanced_api
  Scenario: Add an generic authentication delegation proof to a document
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB"
    And a generic delegation proof created by "#IDB"
    When I add the generic authentication delegation proof "#DelegFromProof" to the document
    Then the other identity is allowed for authentication on the initial identity document

  @advanced_api
  Scenario: Remove an authentication delegation proof from a register document
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB"
    And a delegation proof for document of "#IDA" created by "#IDB"
    And I add the authentication delegation proof "#DelegFromProof" to the document
    When I remove the authentication delegation proof from the document
    Then the delegated registered identity is not allowed for authentication on the document after delegation remove

  @advanced_api
  Scenario: Revoke an authentication delegation proof
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB"
    And a delegation proof for document of "#IDA" created by "#IDB"
    And I add the authentication delegation proof "#DelegFromProof" to the document
    When I revoke the authentication delegation proof
    Then the delegated registered identity is not allowed for authentication on the document after delegation revoke

  @advanced_api
  Scenario: Authentication delegation is still valid if the delegated identity has several owners and the key used in the proof is revoked
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB" and an extra owner "#OtherOwner"
    And one identity delegates authentication to another with extra owner with delegation name "#AnAuthDeleg"
    When the delegated identity owner used for the proof is revoked
    Then the delegated registered identity is still allowed for authentication on the document

  @advanced_api
  Scenario: Authentication delegation is not valid if the delegated identity has several owners and the key used in the proof is removed
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB" and an extra owner "#OtherOwner"
    And one identity delegates authentication to another with extra owner with delegation name "#AnAuthDeleg"
    When the delegated identity owner used for the proof is removed
    Then the delegated registered identity is not allowed for authentication on the document anymore

  @advanced_api
  Scenario: Control delegation is still valid if the delegated identity has several owners and the key used in the proof is revoked
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB" and an extra owner "#OtherOwner"
    And one identity delegates control to another with extra owner with delegation name "#ACtrlDeleg"
    When the delegated identity owner used for the proof is revoked
    Then the delegated registered identity is still allowed for control on the document

  @advanced_api
  Scenario: Control delegation is not valid if the delegated identity has several owners and the key used in the proof is removed
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB" and an extra owner "#OtherOwner"
    And one identity delegates control to another with extra owner with delegation name "#ACtrlDeleg"
    When the delegated identity owner used for the proof is removed
    Then the delegated registered identity is not allowed for control on the document anymore

  @advanced_api
  Scenario: Document controller is allowed for auth and control
    Given a registered identity with name "#IDA"
    And a another registered identity with name "#IDB"
    When I set the controller on my document
    Then the controller is allowed for control and authentication
