using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace gvaduha.twofa
{
    class Facade
    {
    }

    public interface ISecondFactorResult
    {
    }

    public class RegistrationResponse : ISecondFactorResult
    {
        public string xxx = "register me";
    }

    public class LoginFailedResponse : ISecondFactorResult
    {
        public string aaa = "shit u miss";
    }

    
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

    /// <summary>
    /// Gateway to perform second factor auth actions
    /// </summary>
    public class SecondFactorGateway
    {
        public ISecondFactorResult Login(IAccountInformation user)
        {
            return new RegistrationResponse();
            //throw new NotImplementedException();
        }
    }
}
