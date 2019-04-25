using System;
using gvaduha.twofa;

namespace example
{
    class DeliveryGateWay : ISharedSecretKeyDeliveryGateway
    {
        public void SendSharedSecretKey(IAccountDeliveryDetails deliveryDetails, string key)
        {
            // create concrete delivery class and send along with it

            Console.WriteLine($"I sending [{key}] to {deliveryDetails.Identity}");
        }
    }

    class LoginUser : IAccountInformation
    {
        public ScaFactorStatus Status { get; set; }
        public string SharedSecret { get; set; }
        public byte FaultAttempts { get; set; }
        public string Identity { get; }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var config = new SecondFactorGateway.Config(TotpAuthenticationFactorConfig.Default, SharedSecretExchangeConfig.Default);
            var sfgw = new SecondFactorGateway(config,
                new QrCodeGenerator(new QrCodeGenerator.Config(TotpAuthenticationFactorConfig.Default.CodeSize, TotpAuthenticationFactorConfig.Default.CodeStep, "gv@local")),
                new DeliveryGateWay()
                );
            var result = sfgw.Login(new LoginUser());

            switch (result)
            {
                case ConfigurationRequiredResponse r:
                    Console.WriteLine(r.QrCode);
                    break;
                case LoginFailedResponse r:
                    Console.WriteLine("FAILED");
                    break;
                default:
                    throw new InvalidOperationException($"Result type [{result.GetType()}] is unknown");
            }
        }
    }
}
