using System.Security.Cryptography;

namespace LiquidVault.Core.Models;

public static class PasswordPolicy
{
    private static readonly string[] Common = ["password", "password123", "qwertyuiop", "qwerty123", "letmein", "iloveyou", "adminadmin", "welcome123", "1234567890123456", "1111111111111111", "密码密码", "我爱你", "生日快乐", "管理员"];
    private static readonly string[] Groups = ["abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^&*-_=+"];

    public static void ValidateMasterPassword(ReadOnlySpan<char> password)
    {
        if (password.Length is < 16 or > 256) throw new VaultFormatException("主密码长度必须在 16 到 256 个字符之间。");
        var text = password.ToString();
        var normalized = string.Concat(text.Normalize().ToLowerInvariant().Where(c => !char.IsWhiteSpace(c)));
        if (Common.Any(x => normalized == x || normalized.Contains(x + "123", StringComparison.Ordinal))) throw new VaultFormatException("主密码属于常见密码或简单变体。");
        if (text.All(char.IsDigit)) throw new VaultFormatException("主密码不能是纯数字。");
        if (text.Distinct().Count() == 1) throw new VaultFormatException("主密码不能由单一字符重复组成。");
        if (HasLongRun(text, 6)) throw new VaultFormatException("主密码包含过长的重复字符序列。");
    }

    public static int Score(string password)
    {
        var score = 0;
        if (password.Length >= 12) score++;
        if (password.Length >= 18) score++;
        if (password.Any(char.IsLower) && password.Any(char.IsUpper)) score++;
        if (password.Any(char.IsDigit) && password.Any(c => !char.IsLetterOrDigit(c))) score++;
        return score >= 3 ? 3 : score >= 2 ? 2 : 1;
    }

    public static string Generate(int length = 24)
    {
        if (length is < 16 or > 128) throw new ArgumentOutOfRangeException(nameof(length));
        var all = string.Concat(Groups);
        var chars = new List<char>(length);
        foreach (var group in Groups) chars.Add(group[RandomNumberGenerator.GetInt32(group.Length)]);
        while (chars.Count < length) chars.Add(all[RandomNumberGenerator.GetInt32(all.Length)]);
        for (var i = chars.Count - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }
        return new string(chars.ToArray());
    }

    private static bool HasLongRun(string text, int runLength)
    {
        var run = 1;
        for (var i = 1; i < text.Length; i++)
        {
            run = text[i] == text[i - 1] ? run + 1 : 1;
            if (run >= runLength) return true;
        }
        return false;
    }
}
