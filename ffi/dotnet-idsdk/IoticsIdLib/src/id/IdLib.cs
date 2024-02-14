using System.Runtime.InteropServices;

/**
Wrapper class that loads the DLL and exposes the methods as C# code. 
*/
internal partial class IdLib
{
    // Define the struct that matches the return type of most of the functions below
    [StructLayout(LayoutKind.Sequential)]
    public struct StringAndError
    {
        public IntPtr r0;
        public IntPtr r1;
    }

    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    public static partial StringAndError CreateDefaultSeed();

    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial StringAndError MnemonicBip39ToSeed([MarshalAs(UnmanagedType.LPUTF8Str)] string cMnemonic);

    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial StringAndError SeedBip39ToMnemonic([MarshalAs(UnmanagedType.LPUTF8Str)] string cMnemonic);

    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial StringAndError CreateAgentIdentity(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cSeed);

    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial StringAndError RecreateAgentIdentity(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cSeed);

    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial StringAndError CreateTwinIdentity(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cSeed);

    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial StringAndError RecreateTwinIdentity(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cSeed);

    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial StringAndError CreateUserIdentity(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cSeed);

    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial StringAndError RecreateUserIdentity(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cSeed);

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

    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial StringAndError IsAllowedFor([MarshalAs(UnmanagedType.LPUTF8Str)] string cResolverAddress, [MarshalAs(UnmanagedType.LPUTF8Str)] string cToken);

    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial StringAndError CreateAgentAuthToken(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentKeyName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentName,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAgentSeed,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cUserDid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cAudience,
        long durationInSeconds);

    [LibraryImport("lib-iotics-id-sdk")]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    public static partial StringAndError CreateTwinDidWithControlDelegation(
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
