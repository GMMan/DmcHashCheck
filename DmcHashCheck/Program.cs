// See https://aka.ms/new-console-template for more information
using DmcHashCheck;

if (args.Length != 1)
{
    Console.WriteLine($"Usage: DmcHashCheck <firmwarePath>");
    return 1;
}

try
{
    using var stream = File.OpenRead(args[0]);
    HashChecker.CheckFirmware(stream);
}
catch (Exception ex)
{
    Console.WriteLine($"Error while verifying: {ex.Message}");
    return 2;
}

return 0;
