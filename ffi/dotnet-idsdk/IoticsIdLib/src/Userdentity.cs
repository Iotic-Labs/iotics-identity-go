namespace IOTICS;

public class UserIdentity(Identity factory, string seed, string keyName, string id, string did) : PartyIdentity(factory, seed, keyName, id, did)
{

    public void Recreate() 
    {
        Factory.RecreateUserIdentity(Seed, KeyName, Id);
    }

    /// <summary>
    /// Utility method wrapping the factory method UserDelegatesAuthenticationToAgent
    /// </summary>
    /// <param name="agentIdentity">the agent being delegated</param>
    /// <param name="delegationName">the delegation name</param>
    /// <returns></returns>
    public void DelegateAuthentication(AgentIdentity agentIdentity, string delegationName) {
        Factory.UserDelegatesAuthenticationToAgent(agentIdentity, this, delegationName);
    }
}