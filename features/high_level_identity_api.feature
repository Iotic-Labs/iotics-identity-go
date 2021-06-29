Feature: High Level Identity API

  Background:
    Given a resolver exists

  @high_level_api
  Scenario: Create user and agent with authentication delegation
    Given a user seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And a user key name "#KeyUser1"
    And a user issuer name "#user-0"
    And an agent seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And an agent key name "#KeyAgent1"
    And a delegation name "#AuthDelegation"
    And a agent issuer name "#agent-0"
    When I create user and agent with authentication delegation
    Then the user document is created and registered
    Then the agent document is created and registered
    And the user and agent documents are registered with authentication delegation

  @high_level_api
  Scenario: Create a Twin
    Given a twin seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And a twin key name "#KeyTwin1"
    And a twin issuer name "#Twin1"
    When I create a twin
    Then the twin document is created and registered

  @high_level_api
  Scenario: Create a Twin with control delegation
    Given a twin seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And a twin key name "#KeyTwin1"
    And I create a twin
    And an agent seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And an agent key name "#RegAgent1"
    And I create an agent
    And a delegation name "#AuthDelegation"
    When I delegate control
    Then the twin document has control delegation from the agent identity

  @high_level_api
  Scenario: Create an agent token
    Given a user seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And a user key name "#KeyUser1"
    And an agent seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And an agent key name "#KeyAgent1"
    And a delegation name "#AuthDelegation"
    And I create user and agent with authentication delegation
    And the auth token duration is "500s"
    And the target audience is "http://localhost"
    When I create an agent auth token
    Then the auth token is valid

  @high_level_api
  Scenario: Get ownership of a twin
    Given a user seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And a user key name "#RegUserKey1"
    And a user issuer name "#user-0"
    And I create a user
    And a twin seed "8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51"
    And a twin key name "#RegTwinKey1"
    And I create a twin
    And a new owner key name is "#NewOwner"
    When the user takes ownership of the registered twin
    Then the user document is created and registered
    And the twin document is updated with the new owner
