using System;

namespace gvaduha.twofa
{
    #region Gateway responses

    /// <summary>
    /// General result of gateway responses. Uses in pattern matching (make poor's discriminated union type)
    /// </summary>
    public interface ISecondFactorResult {}

    /// <summary>
    /// Response with data for second factor configuration
    /// </summary>
    public class ConfigurationRequiredResponse : ISecondFactorResult
    {
        public readonly string QrCode;

        public ConfigurationRequiredResponse(string qrCode)
        {
            QrCode = qrCode;
        }
    }

    /// <summary>
    /// Second factor login succeeded
    /// </summary>
    public class LoginSuccessResponse : ISecondFactorResult
    {
        public string Reason { get; set; }
    }

    /// <summary>
    /// Second factor code required
    /// </summary>
    public class SecondFactorRequiredResponse : ISecondFactorResult {}

    /// <summary>
    /// Second factor login failed
    /// </summary>
    public class LoginFailedResponse : ISecondFactorResult {}

    /// <summary>
    /// Request for account locking
    /// </summary>
    public class AccountShouldBeLockedResponse : ISecondFactorResult {}
    #endregion


    /// <summary>
    /// Details of SCA for user account
    /// </summary>
    public interface IAccountScaDetails
    {
        /// <summary>
        /// Status of SCA
        /// </summary>
        ScaFactorStatus Status { get; set; }

        /// <summary>
        /// Shared secret using for TOTP
        /// </summary>
        string SharedSecret { get; set; }

        /// <summary>
        /// Current counter of attempts to process SCA
        /// </summary>
        byte FaultAttempts { get; set; }
    }

    /// <summary>
    /// Details (e-mail, post address, etc) for information delivery
    /// </summary>
    public interface IAccountDeliveryDetails
    {
        /// <summary>
        /// Uniq user identity
        /// </summary>
        string Identity { get; }
    }

    /// <summary>
    /// All information for account needed to perform second factor auth
    /// </summary>
    public interface IAccountInformation : IAccountScaDetails, IAccountDeliveryDetails
    {
    }


    #region "Configuration"
    /// <summary>
    /// TOTP algorithm settings
    /// </summary>
    public struct TotpAuthenticationFactorConfig
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="codeSize">Truncate auth code to this value</param>
        /// <param name="codeStep">Auth code valid time frame in seconds</param>
        /// <param name="codeWindow">Auth code frame of tolerance codeWindow (-n..code..+n)</param>
        /// <param name="secretSize">Size of shared secret in symbols</param>
        public TotpAuthenticationFactorConfig(byte codeSize, byte codeStep, byte codeWindow, uint secretSize)
        {
            CodeSize = codeSize;
            CodeStep = codeStep;
            CodeWindow = codeWindow;
            SecretSize = secretSize;
        }

        /// <summary>
        /// Truncate auth code to this value
        /// </summary>
        public readonly byte CodeSize;

        /// <summary>
        /// Auth code valid time frame in seconds
        /// </summary>
        public readonly byte CodeStep;

        /// <summary>
        /// Auth code frame of tolerance codeWindow (-n..code..+n)
        /// </summary>
        public readonly byte CodeWindow;

        /// <summary>
        /// Size of shared secret in symbols
        /// </summary>
        public readonly uint SecretSize;

        /// <summary>
        /// Default configuration
        /// </summary>
        public static TotpAuthenticationFactorConfig Default { get; } = new TotpAuthenticationFactorConfig(6,30,5,32);
    }

    /// <summary>
    /// Configuration of symmetric encryption key
    /// </summary>
    public class SharedSecretExchangeConfig
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="symmetricKeySize">shrink normal (128/256) key size to this value</param>
        /// <param name="symmetricExtendedKeySize">extend shrinked key back to value applicable to algorithm (128/256)</param>
        public SharedSecretExchangeConfig(uint symmetricKeySize, uint symmetricExtendedKeySize)
        {
            SymmetricKeySize = symmetricKeySize;
            SymmetricExtendedKeySize = symmetricExtendedKeySize;
        }

        /// <summary>
        /// Shrink normal (128/256) key size to this value
        /// </summary>
        public readonly uint SymmetricKeySize;
        /// <summary>
        /// Extend shrinked key back to value applicable to algorithm (128/256)
        /// </summary>
        public readonly uint SymmetricExtendedKeySize;

        /// <summary>
        /// Default configuration 80b/128b
        /// </summary>
        public static SharedSecretExchangeConfig Default { get; } = new SharedSecretExchangeConfig(80, 128);
    }
    #endregion

    /// <summary>
    /// Gateway to perform second factor auth actions
    /// </summary>
    public class SecondFactorGateway
    {
        private readonly SecondFactorFacade _facade;

        /// <summary>
        /// SecondFactorGateway configuration
        /// </summary>
        public struct Config
        {
            public Config(TotpAuthenticationFactorConfig totp, SharedSecretExchangeConfig crypto)
            {
                Totp = totp;
                Crypto = crypto;
            }

            public TotpAuthenticationFactorConfig Totp { get; }
            public SharedSecretExchangeConfig Crypto { get; }
        }

        public SecondFactorGateway(Config config, IGraphicCodeGenerator graphicCodeGenerator, ISharedSecretKeyDeliveryGateway deliveryGateway)
        {
            _facade = new SecondFactorFacade(config, graphicCodeGenerator, deliveryGateway);
        }

        /// <summary>
        /// Provides second factor login gateway function
        /// </summary>
        /// <param name="user">user authenticated with first factor</param>
        /// <returns>ISecondFactorResult response depending on user second factor auth settings and login status</returns>
        public ISecondFactorResult Login(IAccountInformation user)
        {
            switch (user.Status)
            {
                case ScaFactorStatus.Disabled:
                    return new LoginSuccessResponse{Reason = "Second factor disabled"};
                case ScaFactorStatus.NotConfigured:
                    var qr = _facade.Configure(user);
                    return new ConfigurationRequiredResponse(qr);
                case ScaFactorStatus.Enabled:
                    return new SecondFactorRequiredResponse();
            }

            throw new NotImplementedException($"User status {user.Status} is invalid");
        }

        public ISecondFactorResult CheckFactor(IAccountInformation user, string totp)
        {
            //if (user.Status != ScaFactorStatus.Enabled)
                throw new NotImplementedException($"User status {user.Status} is invalid");
        }
    }

    class SecondFactorFacade
    {
        private readonly SecondFactorGateway.Config _config;
        private readonly IGraphicCodeGenerator _graphicCodeGenerator;
        private readonly ISharedSecretKeyDeliveryGateway _deliveryGateway;

        public SecondFactorFacade(SecondFactorGateway.Config config, IGraphicCodeGenerator graphicCodeGenerator, ISharedSecretKeyDeliveryGateway deliveryGateway)
        {
            _config = config;
            _graphicCodeGenerator = graphicCodeGenerator;
            _deliveryGateway = deliveryGateway;
        }

        public string Configure(IAccountInformation user)
        {
            // generate and save share secret
            var ss = new TotpAuthenticationFactor(_config.Totp).GenerateSharedSecret();
            user.SharedSecret = ss;
            System.Diagnostics.Debug.Print($"SS on server side: {ss}\n");
            // change state
            user.Status = ScaFactorStatus.Enabled;

            // encrypt shared secret with symmetric key
            var (ssEncrypted, iv, key) = ss.SymmetricCrypt((int) _config.Crypto.SymmetricKeySize);
            System.Diagnostics.Debug.Print($"SS encryption key: {key}\n");
            
            // send symmetric key to user
            _deliveryGateway.SendSharedSecretKey(user, key);

            // create QR
            var visualCode = _graphicCodeGenerator.GenerateEncrypted(ssEncrypted, iv, user.Identity);

            return visualCode;
        }
    }
}
