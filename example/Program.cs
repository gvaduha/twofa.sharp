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
        public string Identity { get; set; }
    }

    class Example
    {
        private readonly SecondFactorGateway _sfgw;
        private LoginUser _user;

        public Example()
        {
            var config = new SecondFactorGateway.Config(TotpAuthenticationFactorConfig.Default, SharedSecretExchangeConfig.Default);
            _sfgw = new SecondFactorGateway(config,
                new QrCodeGenerator(new QrCodeGenerator.Config(TotpAuthenticationFactorConfig.Default.CodeSize, TotpAuthenticationFactorConfig.Default.CodeStep, "gv@local")),
                new DeliveryGateWay()
            );
            _user = new LoginUser()
                {FaultAttempts = 0, SharedSecret = "", Status = ScaFactorStatus.NotConfigured, Identity = "testuser"};
        }

        public void xab()
        {
            var result = _sfgw.Login(new LoginUser());

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

    class Program
    {
        static void Main(string[] args)
        {
            var e = new Example();
        }
    }
}
