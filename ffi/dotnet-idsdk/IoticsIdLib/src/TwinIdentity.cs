namespace IOTICS;

public class TwinIdentity(Identity factory, string seed, string keyName, string id, string did) : PartyIdentity(factory, seed, keyName, id, did)
{
        public void Recreate() 
    {
        Factory.RecreateTwinIdentity(Seed, KeyName, Id);
    }


    public TwinIdentity(Identity factory, AgentIdentity creator, string keyName, string id, string did): this(factory, creator.Seed, keyName, id, did) {

    }

    /// <summary>
    /// Create delegation to a different agent than the creator/controller
    /// </summary>
    /// <param name="agentIdentity">the agent being delegated</param>
    /// <param name="delegationName">the delegation</param>
    /// <returns></returns>
    public void DelegateControl(AgentIdentity agentIdentity, string delegationName) {
        Factory.TwinDelegatesControlToAgent(agentIdentity, this, delegationName);
    }
}