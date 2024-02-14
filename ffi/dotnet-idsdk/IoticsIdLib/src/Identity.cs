using System.Net;

namespace IOTICS;

// Custom RuntimeException class
public class IoticsLibException(string message) : ApplicationException(message)
{
}

public class DelegationException(string message) : IoticsLibException(message) 
{    
}

/** 
Factory class for identity. 
It takes a resolver address as discovered by https://<your_space>.iotics.space/index.json

This class only exposes a subset of the methods of the IOTICS identity library, 
specifically the functions defined in the golang ffi wrapper here
 https://github.com/Iotic-Labs/iotics-identity-go/blob/v3/ffi/ffi_wrapper.go
 
The full spec of the identity is here https://drive.google.com/file/d/1nlJxB08cpYStcunMyhXjOvHStWZEv4ch/view

The full API is here https://github.com/Iotic-Labs/iotics-identity-go/tree/v3/pkg/api

A simple usage of the API is in the file Main.cs

*/
public class Identity(string resolverAddress)
{
    public string ResolverAddress
    {
        get
        {
            return Tools.IsUrl(resolverAddress) ? Tools.RemoveTrailingSlash(resolverAddress) : resolverAddress;
        }
    }


    /// <summary>
    /// Creates a Seed that is then used to initialise the random number generator used to create private keys underpinning the identities.
    /// Important: if a seed is forgotten or lost, the keys and ultimately, identities created with this shim will be lost forever.
    /// </summary>
    /// <returns>the seed string</returns>
    public static string CreateDefaultSeed()
    {
        return Tools.InvokeGoFunction(() => IdLib.CreateDefaultSeed());
    }

    /// <summary>
    /// Seeds can be retrieved by supplying the mnemonics to this method
    /// </summary>
    /// <param name="mnemonics">the mnemonics created with SeedBip39ToMnemonic</param>
    /// <returns>a string with mnemonics separated by a space</returns>
    public static string MnemonicBip39ToSeed(string mnemonics)
    {
        return Tools.InvokeGoFunction(() => IdLib.MnemonicBip39ToSeed(mnemonics));
    }

    /// <summary>
    /// Seeds don't have to be remembered and they can be mapped to human readeable mnemonics easier to pin down or remembered.
    /// </summary>
    /// <param name="seed">a seed</param>
    /// <returns>the mnemonics string separated by space</returns>
    public static string SeedBip39ToMnemonic(string seed)
    {
        return Tools.InvokeGoFunction(() => IdLib.SeedBip39ToMnemonic(seed));
    }

    /// <summary>
    /// Creates an agent identity. This is the identity that your agent application uses to interact with space. The DID of the agent is important to
    /// configure in space for access control
    /// Note that the agent takes a seed. For security purposes, it should be different than that of the user and possibly twins. 
    /// An agent identity can't simply connect to a space. It must have an auth delegation from an user identity. Also, in order to control a twin, it must have control 
    /// delegation on that twin.  
    /// 
    /// The call is idempotent. If called multiple times with the same arguments, it won't override the one present in the resolver.
    /// </summary>
    /// <param name="seed">a seed specific for this agent as created by CreateDefaultSeed</param>
    /// <param name="cKeyName">a key name</param>
    /// <param name="cId">a unique ID in the identity document referring the public key matching this identity</param>
    /// <returns>a new agent identity.</returns>
    public AgentIdentity CreateAgentIdentity(string seed, string cKeyName, string cId)
    {
        string did = Tools.InvokeGoFunction(() => IdLib.CreateAgentIdentity(ResolverAddress, cKeyName, Tools.EnsureHashPrefix(cId), seed));
        return new AgentIdentity(this, seed, cKeyName, cId, did);
    }

    /// <summary>
    /// sometimes it's easier to re-create the identity document in the resolver. Admittedly, for this wrapper, this method isn't going to do anything special 
    /// because the agent identities are created with only a key.
    /// *** this operation wipes out the identity in the resolver ***
    /// </summary>
    /// <param name="seed">a seed specific for this agent as created by CreateDefaultSeed</param>
    /// <param name="cKeyName">a key name</param>
    /// <param name="cId">a unique ID in the identity document referring the public key matching this identity</param>
    /// <returns>the agent identity</returns>
    public AgentIdentity RecreateAgentIdentity(string seed, string cKeyName, string cId)
    {
        string did = Tools.InvokeGoFunction(() => IdLib.RecreateAgentIdentity(ResolverAddress, cKeyName, Tools.EnsureHashPrefix(cId), seed));
        return new AgentIdentity(this, seed, cKeyName, cId, did);
    }

    /// <summary>
    /// Creates a twin identity.   
    /// 
    /// The call is idempotent. If called multiple times with the same arguments, it won't override the one present in the resolver.
    /// </summary>
    /// <param name="seed">a seed specific for this twin as created by CreateDefaultSeed</param>
    /// <param name="cKeyName">a key name</param>
    /// <param name="cId">a unique ID in the identity document referring the public key matching this identity</param>
    /// <returns>a new twin identity.</returns>
    public TwinIdentity CreateTwinIdentity(string seed, string cKeyName, string cId)
    {
        string did = Tools.InvokeGoFunction(() => IdLib.CreateTwinIdentity(ResolverAddress, cKeyName, Tools.EnsureHashPrefix(cId), seed));
        return new TwinIdentity(this, seed, cKeyName, cId, did);
    }

    /// <summary>
    /// sometimes it's easier to re-create the identity document in the resolver.
    /// *** this operation wipes out the identity of this twin in the resolver ***
    /// </summary>
    /// <param name="seed">a seed specific for this twin as created by CreateDefaultSeed</param>
    /// <param name="cKeyName">a key name</param>
    /// <param name="cId">a unique ID in the identity document referring the public key matching this identity</param>
    /// <returns>the twin identity</returns>
    public TwinIdentity RecreateTwinIdentity(string seed, string cKeyName, string cId)
    {
        string did = Tools.InvokeGoFunction(() => IdLib.RecreateTwinIdentity(ResolverAddress, cKeyName, Tools.EnsureHashPrefix(cId), seed));
        return new TwinIdentity(this, seed, cKeyName, cId, did);
    }

    /// <summary>
    /// Creates a user identity. This is the identity that a user uses to authorise an agent to interact with IOTICS. 
    /// The DID of the user identity is important to configure in space for access control.
    /// 
    /// Note that the method takes a seed. For security purposes, it should be different than that of the agent and possibly twins. 
    /// A user won't connect to a space. It must delegate an agent. Without it, the agent won't be able to operate with space.
    /// 
    /// The call is idempotent. If called multiple times with the same arguments, it won't override the one present in the resolver.
    /// 
    /// NOTE: the delegations to an agent are stored in the user identity document. A user can delegate multiple agents. See `UserDelegatesAuthenticationToAgent`.
    /// </summary>
    /// <param name="seed">a seed specific for this user as created by CreateDefaultSeed</param>
    /// <param name="cKeyName">a key name</param>
    /// <param name="cId">a unique ID in the identity document referring the public key matching this identity</param>
    /// <returns>a new user identity.</returns>
    public UserIdentity CreateUserIdentity(string seed, string cKeyName, string cId)
    {
        string did = Tools.InvokeGoFunction(() => IdLib.CreateUserIdentity(ResolverAddress, cKeyName, Tools.EnsureHashPrefix(cId), seed));
        return new UserIdentity(this, seed, cKeyName, cId, did);
    }

    /// <summary>
    /// Recreates the identity in the resolver. It wipes out ALL delegations existing in the document.
    /// </summary>
    /// <param name="seed">a seed specific for this user as created by CreateDefaultSeed</param>
    /// <param name="cKeyName">a key name</param>
    /// <param name="cId">a unique ID in the identity document referring the public key matching this identity</param>
    /// <returns></returns>
    public UserIdentity RecreateUserIdentity(string seed, string cKeyName, string cId)
    {
        string did = Tools.InvokeGoFunction(() => IdLib.RecreateUserIdentity(ResolverAddress, cKeyName, Tools.EnsureHashPrefix(cId), seed));
        return new UserIdentity(this, seed, cKeyName, cId, did);
    }


    /// <summary>
    /// Creates a twin identity and automatically creates the control delegation for the agent identity. 
    /// It's a convenience method. More advanced and fine grained control methods on twin identities are not exposed in this shim
    /// </summary>
    /// <param name="creator">the agent creating this twin</param>
    /// <param name="cKeyName">a key name</param>
    /// <param name="cId">a unique ID in the identity document referring the public key matching this identity</param>
    /// <returns>the twin identity with the delegation already setup</returns>
    public TwinIdentity CreateTwinIdentityWithControlDelegation(AgentIdentity creator, string cKeyName, string cId)
    {
        string did = Tools.InvokeGoFunction(() => IdLib.CreateTwinDidWithControlDelegation(
            ResolverAddress, creator.Did, creator.KeyName, creator.Id, creator.Seed, cKeyName, cId
        ));
        return new TwinIdentity(this, creator, cKeyName, cId, did);
    }

    /// <summary>
    /// Creates a delegation from a user to an agent.
    /// </summary>
    /// <param name="agentIdentity">the identity of the agent being delegated</param>
    /// <param name="userIdentity">the identity of the delegating user</param>
    /// <param name="cDelegationName">the unique name of this delegation</param>
    /// <returns>throws DelegationException if an error occurs</returns>
    public void UserDelegatesAuthenticationToAgent(
        AgentIdentity agentIdentity,
        UserIdentity userIdentity,
        string cDelegationName
    ) {
        string? result = Tools.InvokeGoFunction(() => IdLib.UserDelegatesAuthenticationToAgent(ResolverAddress, 
            agentIdentity.Did, agentIdentity.KeyName, Tools.EnsureHashPrefix(agentIdentity.Id), agentIdentity.Seed,
            userIdentity.Did, userIdentity.KeyName, Tools.EnsureHashPrefix(userIdentity.Id), userIdentity.Seed,
            Tools.EnsureHashPrefix(cDelegationName)));
        
        if(result != null) {
            throw new DelegationException(result);
        }
    }

    /// <summary>
    /// In case another agent (other than the creator) needs delegation. 
    /// This method is of limited use at this stage since, for it to work, both keys of the principals need to be available.
    /// It should only be sufficient for the agent to submit a proof which is a public value. 
    /// 
    /// </summary>
    /// <param name="agentIdentity">the identity of the agent being delegated</param>
    /// <param name="twinIdentity">the identity of the delegating twin</param>
    /// <param name="cDelegationName">the unique name of this delegation</param>
    /// <returns>throws DelegationException if an error occurs</returns>
    public void TwinDelegatesControlToAgent(
        AgentIdentity agentIdentity,
        TwinIdentity twinIdentity,
        string cDelegationName
    ) {
        string? result = Tools.InvokeGoFunction(() => IdLib.TwinDelegatesControlToAgent(ResolverAddress, 
            agentIdentity.Did, agentIdentity.KeyName, Tools.EnsureHashPrefix(agentIdentity.Id), agentIdentity.Seed,
            twinIdentity.Did, twinIdentity.KeyName, Tools.EnsureHashPrefix(twinIdentity.Id), twinIdentity.Seed,
            Tools.EnsureHashPrefix(cDelegationName)));
        if(result != null) {
            throw new DelegationException(result);
        }
    }

    /// <summary>
    /// creates a valid token enabling the agent to call APIs to the space.
    /// A token is valid if the agent identity exists and if the user supplied has a valid delegation.
    /// the duration in seconds determins the temporal validity of this token.
    /// </summary>
    /// <param name="agentIdentity">the agent</param>
    /// <param name="userDid">the delegating user. if a delegation exists for this user, the call will be successful</param>
    /// <param name="audience">the space name (unused at this stage)</param>
    /// <param name="duration">duration in seconds</param>
    /// <returns></returns>
    public static string CreateAgentAuthToken(AgentIdentity agentIdentity, string userDid, string audience, long duration)
    {
        return Tools.InvokeGoFunction(() => IdLib.CreateAgentAuthToken(agentIdentity.Did, agentIdentity.KeyName, agentIdentity.Id, agentIdentity.Seed, userDid, audience, duration));
    }

}
