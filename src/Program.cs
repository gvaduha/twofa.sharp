using System;
using System.Diagnostics;
using gvaduha.twofa;

namespace twofaproto
{
    class Program
    {
        static void Main(string[] args)
        {
            Context ctx = new Context();
            StateNotConfigured snc = new StateNotConfigured();
            snc.Enter(ctx);
            var svg = ctx.StateExecutionResult;
            Console.WriteLine(svg);
        }
    }
}
