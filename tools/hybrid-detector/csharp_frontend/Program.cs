using System.Runtime.InteropServices;

namespace HybridDetector;

class Program
{
    [DllImport("hybrid_backend.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr get_system_status();

    static void Main(string[] args)
    {
        Console.WriteLine("=== Hybrid Detector (C# + C++) ===\n");

        IntPtr ptr = get_system_status();
        
        string status = Marshal.PtrToStringAnsi(ptr) ?? "Erro ao obter status";

        Console.WriteLine("Status do Sistema (via C++):\n");
        Console.WriteLine(status);

        Console.WriteLine("\nPressione qualquer tecla para sair...");
        Console.ReadKey();
    }
}