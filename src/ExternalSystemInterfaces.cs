
using System.Drawing;
using System.Text;
using QRCoder;

namespace gvaduha.twofa
{

    /// <summary>
    /// Decouples method of delivery symmetric key to decode shared secret
    /// </summary>
    interface ISharedSecretKeyDelivery
    {
        /// <summary>
        /// Deliver the symmetric key used to encode shared secret to the user
        /// </summary>
        /// <param name="deliveryDetails">account delivery details</param>
        /// <param name="sharedSecret"></param>
        void SendSharedSecretKey(IAccountDeliveryDetails deliveryDetails, string sharedSecret);
    }

    /// <summary>
    /// Shared secret code visualization
    /// </summary>
    interface IGraphicCodeGenerator
    {
        /// <summary>
        /// Generates visual representation of symmetrically encrypted shared secred as HTML section
        /// </summary>
        /// <param name="sharedSecred">encrypted shared secret</param>
        /// <param name="iv">initialization vector</param>
        /// <param name="identity">user identity for TOTP</param>
        /// <returns></returns>
        string GenerateEncrypted(string sharedSecred, string iv, string identity);
    }


    /// <summary>
    /// QR code generator
    /// </summary>
    class QrCodeGenerator : IGraphicCodeGenerator
    {
        public struct Config
        {
            public byte PixelSize;
            public byte CodeSize;
            public byte CodeStep;
            public string Issuer;

            public Config(byte codeSize, byte codeStep, string issuer, byte pixelSize = 3)
            {
                PixelSize = pixelSize;
                CodeSize = codeSize;
                CodeStep = codeStep;
                Issuer = issuer;
            }
        }

        private readonly Config _config;

        public QrCodeGenerator(Config config)
        {
            _config = config;
        }

        public string GenerateEncrypted(string sharedSecred, string iv, string identity)
        {
            var otppl = new PayloadGenerator.OneTimePassword();
            otppl.Secret = sharedSecred;
            otppl.Issuer = _config.Issuer;
            otppl.Label = identity;
            otppl.Digits = _config.CodeSize;
            otppl.Period = _config.CodeStep;
            var sb = new StringBuilder(otppl.ToString());
            sb.Append("&extver=1").Append("&iv=").Append(iv);

            using (var qrGenerator = new QRCodeGenerator())
            {
                using (var qrCodeData = qrGenerator.CreateQrCode(sb.ToString(), QRCodeGenerator.ECCLevel.L)) // L is 7% max lost to confuse remote optical capture
                {
                    using (var qrCode = new SvgQRCode(qrCodeData))
                    {
                        return qrCode.GetGraphic(_config.PixelSize);
                    }
                }
            }
        }
    }

    /********************************************************/
    // PURE MOCKS
    /********************************************************/
    //TODO: Connect to real systems
    class EmailGateWay : ISharedSecretKeyDelivery
    {
        public void SendSharedSecretKey(IAccountDeliveryDetails deliveryDetails, string sharedSecret)
        {}
    }

    class ApplicationUser : IAccountDeliveryDetails
    {
        public string Identity { get; }
    }
}
