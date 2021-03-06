Feature: Identity API

  Scenario: Create user identity with default seed method
    Given a user seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And a user key name "#KeyUser1"
    When I create a user
    Then the "user" register document is created
    And the associated "user" identity is returned
    And the "user" owns the document

  Scenario: Create user identity with legacy seed method
    Given a user seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And a user key name "#KeyUser1"
    And the legacy seed method
    When I create a user
    Then the "user" register document is created
    And the associated "user" identity is returned
    And the "user" owns the document

  Scenario: Create agent identity with default seed method
    Given an agent seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And an agent key name "#KeyAgent1"
    When I create an agent
    Then the "agent" register document is created
    And the associated "agent" identity is returned
    And the "agent" owns the document

  Scenario: Create agent identity with legacy seed method
    Given an agent seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And an agent key name "#KeyAgent1"
    And the legacy seed method
    When I create an agent
    Then the "agent" register document is created
    And the associated "agent" identity is returned
    And the "agent" owns the document

  Scenario: Create twin identity with default seed method
    Given a twin seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And a twin key name "#KeyTwin1"
    When I create a twin
    Then the "twin" register document is created
    And the associated "twin" identity is returned
    And the "twin" owns the document

  Scenario: Create twin identity with legacy seed method
    Given a twin seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And a twin key name "#KeyTwin1"
    And the legacy seed method
    When I create a twin
    Then the "twin" register document is created
    And the associated "twin" identity is returned
    And the "twin" owns the document

  Scenario: Create user identity overriding previously created identity
    Given an existing registered "user" identity
    When I create the "user" overriding the document with a new name
    Then the "user" document is updated with the new name

  Scenario: Create agent identity overriding previously created identity
    Given an existing registered "agent" identity
    When I create the "agent" overriding the document with a new name
    Then the "agent" document is updated with the new name

  Scenario: Create twin identity overriding previously created identity
    Given an existing registered "twin" identity
    When I create the "twin" overriding the document with a new name
    Then the "twin" document is updated with the new name

  Scenario: Get existing user identity from secrets
    Given a user seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And a user key name "#KeyUser1" from a registered identity
    When I get the "user" identity
    Then the identity is valid

  Scenario: Get existing agent identity from secrets
    Given an agent seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And an agent key name "#KeyAgent1" from a registered identity
    When I get the "agent" identity
    Then the identity is valid

  Scenario: Get existing twin identity from secrets
    GivenGiven a twin seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And a twin key name "#KeyTwin1" from a registered identity
    When I get the "twin" identity
    Then the identity is valid

  @broken
  Scenario: User delegates authentication to agent
    Given a registered user
    And a registered agent
    And a delegation name "#AuthDelegation"
    When User delegates authentication to agent
    Then the "user" document is updated with the agent authentication delegation

  @broken
  Scenario: Twin delegates control to agent
    Given a registered twin
    And a registered agent
    And a delegation name "#AuthDelegation"
    When Twin delegates control to agent
    Then the "twin" document is updated with the agent authentication delegation

  Scenario: Set document controller
    Given a registered identity with name "#RegID1"
    And a controller issuer
    When I set the identity register document "controller"
    Then the document is updated with the new "controller"

  Scenario: Set document creator
    Given a registered identity with name "#RegID2"
    And a creator
    When I set the identity register document "creator"
    Then the document is updated with the new "creator"

  Scenario: Revoke a document
    Given a not revoked registered identity
    When I revoke the identity register document
    Then the document is revoked

  Scenario: Get a registered document
    Given an existing registered identity
    When I get the registered document
    Then the corresponding document is returned

  Scenario: Verify a valid register document
    Given an existing registered document
    When I verify the document
    Then the document is valid

  Scenario: Verify an corrupted register document
    Given a corrupted registered document
    When I verify the document
    Then a validation error is raised

  Scenario: Create authentication token without authentication delegation
    Given a register user document
    And a register agent document "without" authentication delegation
    When I create an authentication token from the agent "without" delegation
    Then the token "is not" authorized for authentication

  Scenario: Create authentication token with authentication delegation
    Given a register user document
    And a register agent document "with" authentication delegation
    When I create an authentication token from the agent "with" delegation
    Then the token "is" authorized for authentication

  Scenario: Add new owner to a register document
    Given a new owner key name an registered identity register
    When I add a new owner
    Then the new owner key has been added to the document

  Scenario: Remove owner from a register document
    Given an owner key name an registered identity register
    When I remove a owner
    Then the key has been removed from the document
