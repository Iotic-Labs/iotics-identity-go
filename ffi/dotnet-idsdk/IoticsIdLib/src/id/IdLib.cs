using System.Runtime.InteropServices;

/**
Wrapper class that loads the DLL and exposes the methods as C# code. 
*/
internal partial class IdLib
{
    // Define the struct that matches the return type of CreateDefaultSeed in Go
    [StructLayout(LayoutKind.Sequential)]
    public struct Return
    {
        public IntPtr r0;
        public IntPtr r1;
    }

    // Declare the P/Invoke function
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    public static partial Return CreateDefaultSeed();

    // Declare the P/Invoke function for MnemonicBip39ToSeed
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return MnemonicBip39ToSeed([MarshalAs(UnmanagedType.LPStr)] string cMnemonic);

    // Declare the P/Invoke function for SeedBip39ToMnemonic
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return SeedBip39ToMnemonic([MarshalAs(UnmanagedType.LPStr)] string cMnemonic);

    // Declare the P/Invoke function for CreateAgentIdentity
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return CreateAgentIdentity(
        [MarshalAs(UnmanagedType.LPStr)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPStr)] string cKeyName,
        [MarshalAs(UnmanagedType.LPStr)] string cName,
        [MarshalAs(UnmanagedType.LPStr)] string cSeed);

    // Declare the P/Invoke function for RecreateAgentIdentity
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return RecreateAgentIdentity(
        [MarshalAs(UnmanagedType.LPStr)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPStr)] string cKeyName,
        [MarshalAs(UnmanagedType.LPStr)] string cName,
        [MarshalAs(UnmanagedType.LPStr)] string cSeed);

    // Declare the P/Invoke function for CreateTwinIdentity
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return CreateTwinIdentity(
        [MarshalAs(UnmanagedType.LPStr)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPStr)] string cKeyName,
        [MarshalAs(UnmanagedType.LPStr)] string cName,
        [MarshalAs(UnmanagedType.LPStr)] string cSeed);

    // Declare the P/Invoke function for RecreateTwinIdentity
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return RecreateTwinIdentity(
        [MarshalAs(UnmanagedType.LPStr)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPStr)] string cKeyName,
        [MarshalAs(UnmanagedType.LPStr)] string cName,
        [MarshalAs(UnmanagedType.LPStr)] string cSeed);

    // Declare the P/Invoke function for CreateAgentIdentity
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return CreateUserIdentity(
        [MarshalAs(UnmanagedType.LPStr)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPStr)] string cKeyName,
        [MarshalAs(UnmanagedType.LPStr)] string cName,
        [MarshalAs(UnmanagedType.LPStr)] string cSeed);

    // Declare the P/Invoke function for RecreateAgentIdentity
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return RecreateUserIdentity(
        [MarshalAs(UnmanagedType.LPStr)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPStr)] string cKeyName,
        [MarshalAs(UnmanagedType.LPStr)] string cName,
        [MarshalAs(UnmanagedType.LPStr)] string cSeed);


    // Declare the P/Invoke function for UserDelegatesAuthenticationToAgent
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial IntPtr UserDelegatesAuthenticationToAgent(
        [MarshalAs(UnmanagedType.LPStr)] string cResolverAddress,

        [MarshalAs(UnmanagedType.LPStr)] string cAgentDid,
        [MarshalAs(UnmanagedType.LPStr)] string cAgentKeyName,
        [MarshalAs(UnmanagedType.LPStr)] string cAgentName,
        [MarshalAs(UnmanagedType.LPStr)] string cAgentSeed,
        
        [MarshalAs(UnmanagedType.LPStr)] string cUserDid,
        [MarshalAs(UnmanagedType.LPStr)] string cUserKeyName,
        [MarshalAs(UnmanagedType.LPStr)] string cUserName,
        [MarshalAs(UnmanagedType.LPStr)] string cUserSeed,
        
        [MarshalAs(UnmanagedType.LPStr)] string cDelegationName);

    // Declare the P/Invoke function for TwinDelegatesControlToAgent
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial IntPtr TwinDelegatesControlToAgent(
        [MarshalAs(UnmanagedType.LPStr)] string cResolverAddress,

        [MarshalAs(UnmanagedType.LPStr)] string cAgentDid,
        [MarshalAs(UnmanagedType.LPStr)] string cAgentKeyName,
        [MarshalAs(UnmanagedType.LPStr)] string cAgentName,
        [MarshalAs(UnmanagedType.LPStr)] string cAgentSeed,

        [MarshalAs(UnmanagedType.LPStr)] string cTwinDid,
        [MarshalAs(UnmanagedType.LPStr)] string cTwinKeyName,
        [MarshalAs(UnmanagedType.LPStr)] string cTwinName,
        [MarshalAs(UnmanagedType.LPStr)] string cTwinSeed,

        [MarshalAs(UnmanagedType.LPStr)] string cDelegationName);

    // Declare the P/Invoke function for IsAllowedFor
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return IsAllowedFor([MarshalAs(UnmanagedType.LPStr)] string cResolverAddress, [MarshalAs(UnmanagedType.LPStr)] string cToken);

    // Declare the P/Invoke function for CreateAgentAuthToken
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return CreateAgentAuthToken(
        [MarshalAs(UnmanagedType.LPStr)] string cAgentDid,
        [MarshalAs(UnmanagedType.LPStr)] string cAgentKeyName,
        [MarshalAs(UnmanagedType.LPStr)] string cAgentName,
        [MarshalAs(UnmanagedType.LPStr)] string cAgentSeed,
        [MarshalAs(UnmanagedType.LPStr)] string cUserDid,
        [MarshalAs(UnmanagedType.LPStr)] string cAudience,
        long durationInSeconds);

    // Declare the P/Invoke function for CreateTwinDidWithControlDelegation
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial Return CreateTwinDidWithControlDelegation(
        [MarshalAs(UnmanagedType.LPStr)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPStr)] string cAgentDid,
        [MarshalAs(UnmanagedType.LPStr)] string cAgentKeyName,
        [MarshalAs(UnmanagedType.LPStr)] string cAgentName,
        [MarshalAs(UnmanagedType.LPStr)] string cAgentSeed,
        [MarshalAs(UnmanagedType.LPStr)] string cTwinKeyName,
        [MarshalAs(UnmanagedType.LPStr)] string cTwinName);


    // ===============

    // Declare a helper method to convert IntPtr to string and free memory
    public static string? PtrToStringAndFree(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
            return null;

        string? result = Marshal.PtrToStringAnsi(ptr);
        FreeUpCString(ptr); // Assuming your Go library has a function to free the allocated memory
        return result;
    }

    // Declare a function to free the allocated memory
    [LibraryImport("lib-iotics-id-sdk.win.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static partial void FreeUpCString(IntPtr ptr);

}
