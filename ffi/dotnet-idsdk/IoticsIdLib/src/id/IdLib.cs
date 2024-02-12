using System.Runtime.InteropServices;

/**
Wrapper class that loads the DLL and exposes the methods as C# code. 
*/
internal partial class IdLib
{
    // Define the struct that matches the return type of most of the functions below
    [StructLayout(LayoutKind.Sequential)]
    public struct Return
    {
        public IntPtr r0;
        public IntPtr r1;
    }

    // Declare the P/Invoke function
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    public static partial Return CreateDefaultSeed();

    // Declare the P/Invoke function for MnemonicBip39ToSeed
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return MnemonicBip39ToSeed([MarshalAs(UnmanagedType.LPUTF8Str)] string cMnemonic);

    // Declare the P/Invoke function for SeedBip39ToMnemonic
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return SeedBip39ToMnemonic([MarshalAs(UnmanagedType.LPUTF8Str)] string cMnemonic);

    // Declare the P/Invoke function for CreateAgentIdentity
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return CreateAgentIdentity(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cSeed);

    // Declare the P/Invoke function for RecreateAgentIdentity
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return RecreateAgentIdentity(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cSeed);

    // Declare the P/Invoke function for CreateTwinIdentity
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return CreateTwinIdentity(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cSeed);

    // Declare the P/Invoke function for RecreateTwinIdentity
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return RecreateTwinIdentity(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cSeed);

    // Declare the P/Invoke function for CreateUserIdentity
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return CreateUserIdentity(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cSeed);

    // Declare the P/Invoke function for RecreateUserIdentity
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return RecreateUserIdentity(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cSeed);


    // Declare the P/Invoke function for UserDelegatesAuthenticationToAgent
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial IntPtr UserDelegatesAuthenticationToAgent(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,

        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentSeed,
        
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cUserDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cUserKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cUserName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cUserSeed,
        
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cDelegationName);

    // Declare the P/Invoke function for TwinDelegatesControlToAgent
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial IntPtr TwinDelegatesControlToAgent(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,

        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentSeed,

        [MarshalAs(UnmanagedType.LPUTF8Str)] string cTwinDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cTwinKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cTwinName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cTwinSeed,

        [MarshalAs(UnmanagedType.LPUTF8Str)] string cDelegationName);

    // Declare the P/Invoke function for IsAllowedFor
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return IsAllowedFor([MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress, [MarshalAs(UnmanagedType.LPUTF8Str)] string cToken);

    // Declare the P/Invoke function for CreateAgentAuthToken
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return CreateAgentAuthToken(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentSeed,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cUserDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAudience,
        long durationInSeconds);

    // Declare the P/Invoke function for CreateTwinDidWithControlDelegation
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return CreateTwinDidWithControlDelegation(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentSeed,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cTwinKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cTwinName);


    // ===============

    // Declare a helper method to convert IntPtr to string and free memory
    public static string? PtrToStringAndFree(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
            return null;

        string? result = Marshal.PtrToStringAnsi(ptr);
        FreeUpCString(ptr);
        return result;
    }

    // Declare a function to free the allocated memory
    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static partial void FreeUpCString(IntPtr ptr);

}
