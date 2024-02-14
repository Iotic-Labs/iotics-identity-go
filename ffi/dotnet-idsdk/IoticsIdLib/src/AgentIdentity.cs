namespace IOTICS;

public class AgentIdentity(Identity factory, string seed, string keyName, string id, string did) : PartyIdentity(factory, seed, keyName, id, did)
{
    public void Recreate() 
    {
        Factory.RecreateAgentIdentity(Seed, KeyName, Id);
    }
}