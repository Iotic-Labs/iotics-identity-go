using IOTICS;
class Program {
 // Example of usage
    public static int Main(string[] args)
    {
        string RESOLVER = args[0];
        try
        {
            string seed = Identity.CreateDefaultSeed();
            Console.WriteLine("A new seed: " + seed);

            string mnemonics = Identity.SeedBip39ToMnemonic(seed);
            Console.WriteLine("Use these mnemonics instead of remembering the seed: " + mnemonics);

            string recoveredSeed = Identity.MnemonicBip39ToSeed(mnemonics);
            Console.WriteLine("Recovered seed: " + recoveredSeed);

            Identity identity = new(RESOLVER);

            AgentIdentity agentId = identity.CreateAgentIdentity(seed, "agentKeyName", "#agentName");
            Console.WriteLine("Agent identity: " + agentId);

            UserIdentity userId = identity.CreateUserIdentity(seed, "userKeyName", "#userName");
            Console.WriteLine("User identity: " + userId);

            TwinIdentity twinId = identity.CreateTwinIdentity(seed, "twinKeyName", "#twinName");
            Console.WriteLine("Twin identity: " + twinId);

            TwinIdentity twinIdWithCD = identity.CreateTwinIdentityWithControlDelegation(agentId, "twinKeyName", "#twinName");
            Console.WriteLine("Twin identity with CD: " + twinIdWithCD);

            // convenience method wrapping UserIdentity#UserDelegatesAuthenticationToAgent
            userId.DelegateAuthentication(agentId, "#delegation1");
            // string userDelegResult = identity.UserDelegatesAuthenticationToAgent(agentId, userId, "#delegation1");            
            Console.WriteLine("User delegating to agent 1: OK");

            AgentIdentity agentId2 = identity.CreateAgentIdentity(Identity.CreateDefaultSeed(), "agentKeyName2", "#agentName2");
            Console.WriteLine("Agent2 identity: " + agentId2);

            // direct call to the Twin delegation functionality, also available as a wrapper call in the TwinIdentity
            identity.TwinDelegatesControlToAgent(agentId2, twinId, "#delegation1");
            // string twinDelegResult = twinId.DelegateControl(agentId2, "#delegation1");
            Console.WriteLine("Twin delegating to agent2: OK");

            string token = Identity.CreateAgentAuthToken(agentId, userId.Did, "foo", 10L);
            Console.WriteLine("Token 1: " + token);
            token = Identity.CreateAgentAuthToken(agentId, userId.Did, "foo", 10L);
            Console.WriteLine("Token 2: " + token);

            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
            return -1;
        }
    }

}
