namespace IOTICS;

class Tools {
    
    
    public static string InvokeGoFunction(Func<IdLib.Return> goFunction)
    {
        string? error;
        IdLib.Return result;

        try
        {
            // Call the Go function
            result = goFunction.Invoke();
        }
        catch (Exception ex)
        {
            // Handle any unexpected exceptions
            throw new InvalidOperationException($"Exception when invoking method: {ex.Message}");
        }

        // Check for errors in r1 and throw an exception if necessary
        error = IdLib.PtrToStringAndFree(result.r1);
        if (error != null)
        {
            throw new IoticsLibException(error);
        }

        // Convert r0 to a string and free memory
        string? value = IdLib.PtrToStringAndFree(result.r0);

        if (value == null)
        {
            throw new IoticsLibException("unexpected null result");
        }
        return value;
    }
    
    public static string? InvokeGoFunction(Func<IntPtr> goFunction)
    {
        IntPtr result;

        try
        {
            // Call the Go function
            result = goFunction.Invoke();
        }
        catch (Exception ex)
        {
            // Handle any unexpected exceptions
            throw new InvalidOperationException($"Exception when invoking method", ex);
        }

        // Handle the case where the Go function returns nil
        if (result == IntPtr.Zero)
        {
            return null;
        }

        // Convert r0 to a string and free memory
        string? value = IdLib.PtrToStringAndFree(result);

        if (value == null)
        {
            throw new IoticsLibException("unexpected null result");
        }
        return value;
    }

    // Check if the given string is a URL
    public static bool IsUrl(string input)
    {
        return Uri.TryCreate(input, UriKind.Absolute, out _);
    }

    // Remove the trailing slash from the string
    public static string RemoveTrailingSlash(string input)
    {
        return input.TrimEnd('/');
    }

    public static string EnsureHashPrefix(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            throw new ArgumentException("Input string cannot be null or empty.");
        }

        if (input.IndexOf('#') > 0)
        {
            throw new ArgumentException("The '#' character must be present only at the beginning of the string.");
        }

        // Check if the first character is '#'
        if (input[0] != '#')
        {
            // If not, add '#' as the first character
            return '#' + input;
        }

        // If it starts with '#', return the original string
        return input;
    }

    public static string GetLastNCharacters(string input, int n)
    {
        if (!string.IsNullOrEmpty(input) && input.Length >= n)
        {
            return input[^n..];
        }
        else
        {
            return input;
        }
    }
}