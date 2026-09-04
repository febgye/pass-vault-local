namespace LiquidVault.Core.Models;

public class VaultException : Exception
{
    public VaultException(string message) : base(message) { }
    public VaultException(string message, Exception innerException) : base(message, innerException) { }
}

public sealed class VaultAuthenticationException : VaultException
{
    public VaultAuthenticationException() : base("主密码错误，或保险库已经损坏。") { }
}

public sealed class VaultFormatException : VaultException
{
    public VaultFormatException(string message) : base(message) { }
    public VaultFormatException(string message, Exception innerException) : base(message, innerException) { }
}

public sealed class VaultBusyException : VaultException
{
    public VaultBusyException() : base("保险库正被另一个程序实例使用。") { }
}
