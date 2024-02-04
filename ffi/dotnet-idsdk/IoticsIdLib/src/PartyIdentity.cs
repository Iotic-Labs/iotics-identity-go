namespace IOTICS;

public abstract class PartyIdentity(Identity factory, string seed, string keyName, string id, string did)
{
    public string KeyName { get; } = keyName;
    public string Id { get; } = id;
    public string Did { get; } = did;
    public string Seed { get; } = seed;

    
    public Identity Factory { get; } = factory;


    public override string ToString()
    {
        string className = GetType().Name;
        // Customize the string representation based on your class properties
        return $"Key={KeyName}, Id={Id}, Did={Did}, Seed={"..." + Tools.GetLastNCharacters(Seed, 5)} Resolver={Factory.ResolverAddress}";
    }
}