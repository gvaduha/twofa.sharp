using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using gvaduha.twofa;

namespace example
{
    class DeliveryGateWay : ISharedSecretKeyDeliveryGateway
    {
        public void SendSharedSecretKey(IAccountDeliveryDetails deliveryDetails, string key)
        {
            // create concrete delivery class and send along with it

            Console.WriteLine($"I'm sending [{key}] to {deliveryDetails.Identity}");
        }
    }

    class LoginUser : IAccountInformation
    {
        public ScaFactorStatus Status { get; set; }
        public string SharedSecret { get; set; }
        public byte FaultAttempts { get; set; }
        public string Identity { get; set; }
    }

    class Mapping : Attribute
    {
        public string _map;
        public Mapping(string s) => _map = s;
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

        [Mapping("Login")]
        public string getLoginRequest()
        {
            var result = _sfgw.Login(_user);

            switch (result)
            {
                case ConfigurationRequiredResponse r:
                    return r.QrCode;
                case LoginFailedResponse r:
                    return "<H1>FAILED</H1>";
                default:
                    throw new InvalidOperationException($"Result type [{result.GetType()}] is unknown");
            }
        }

        [Mapping("Decode")]
        public string getDecodeRequest(string secret, string iv, string key)
        {
            return $"<H1>{secret.SymmetricDecript(iv, key)}</H1>";
        }


        private void drawDefault(HttpListenerContext ctx)
        {
            string @base = ctx.Request.Url.Segments[0].ToString();
            string html = $"<A href=Login>Login</A><br><A href=Reset>Reset</A>"+
                          $"<br><A href=\"javascript:window.location.href='/Decode/'+document.getElementById('secret').value+'/'+document.getElementById('iv').value+'/'+document.getElementById('key').value\"/>Decode QR</A><input type='text' id='secret' placeholder='secret'><input type='text' id='iv' placeholder='iv'><input type='text' id='key' placeholder='key'>";
            ctx.Response.OutputStream.Write(Encoding.ASCII.GetBytes(html));
        }

        public void Serve()
        {
            Console.WriteLine("Serving@8080 (if failed read https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/configuring-http-and-https)");
            var listener = new HttpListener();
            listener.Prefixes.Add("http://+:8080/");
            listener.Start();
            while (true)
            {
                HttpListenerContext ctx = listener.GetContext();
                ThreadPool.QueueUserWorkItem((_) =>
                {
                    try
                    {
                        string methodName = ctx.Request.Url.Segments[1].Replace("/", "");
                        string[] strParams = ctx.Request.Url
                            .Segments
                            .Skip(2)
                            .Select(s => s.Replace("/", ""))
                            .ToArray();

                        var method = this.GetType()
                            .GetMethods()
                            .Where(mi =>
                                mi.GetCustomAttributes(true)
                                    .Any(attr => attr is Mapping && ((Mapping) attr)._map == methodName))
                            .First();

                        object[] @params = method.GetParameters()
                            .Select((p, i) => Convert.ChangeType(strParams[i], p.ParameterType))
                            .ToArray();

                        object ret = method.Invoke(this, @params);
                        string retstr = ret?.ToString(); //JsonConvert.SerializeObject(ret);
                        ctx.Response.ContentType = "text/html";
                        ctx.Response.OutputStream.Write(Encoding.ASCII.GetBytes(retstr));
                    }
                    catch (Exception)
                    {
                        drawDefault(ctx);
                    }
                });
            }
        }
    }


    class Program
    {
        static void Main(string[] args)
        {
            var e = new Example();
            e.Serve();
        }
    }
}
