﻿using System.Text;
using QRCoder;

namespace gvaduha.twofa
{
    /// <summary>
    /// Decouples method of delivery symmetric key to decode shared secret
    /// </summary>
    public interface ISharedSecretKeyDeliveryGateway
    {
        /// <summary>
        /// Deliver the symmetric key used to encode shared secret to the user
        /// </summary>
        /// <param name="deliveryDetails">account delivery details</param>
        /// <param name="key">symmetric key to decrypt shared secret</param>
        void SendSharedSecretKey(IAccountDeliveryDetails deliveryDetails, string key);
    }

    /// <summary>
    /// Shared secret code visualization
    /// </summary>
    public interface IGraphicCodeGenerator
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
    /// Default implementation of QR code generator
    /// </summary>
    public class QrCodeGenerator : IGraphicCodeGenerator
    {
        public struct Config
        {
            public byte PixelSize { get; }
            public byte CodeSize { get; }
            public byte CodeStep { get; }
            public string Issuer { get; }

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

        /// <summary>
        /// Generates QR for shared secred and includes iv and identity
        /// </summary>
        /// <param name="sharedSecred">QR payload</param>
        /// <param name="iv">extened property iv used to transfer initialization vector</param>
        /// <param name="identity">user's identity can be used to support several accounts in one app scope</param>
        /// <returns></returns>
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
}
