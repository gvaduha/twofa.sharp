using System;
using gvaduha.twofa;

namespace example
{
    class Program
    {
        class LoginUser : IAccountInformation
        {
            public ScaFactorStatus Status { get; set; }
            public string SharedSecret { get; set; }
            public byte FaultAttempts { get; set; }
            public string Identity { get; }
        }

        static void Main(string[] args)
        {
            var sfgw = new SecondFactorGateway();
            var result = sfgw.Login(new LoginUser());

            switch (result)
            {
                case RegistrationResponse r:
                    Console.WriteLine(r.xxx);
                    break;
                case LoginFailedResponse r:
                    Console.WriteLine(r.aaa);
                    break;
                default:
                    throw new InvalidOperationException($"Result type [{result.GetType()}] is unknown");
            }
        }
    }
}
