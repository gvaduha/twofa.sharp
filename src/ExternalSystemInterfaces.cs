
namespace gvaduha.twofa
{
    /// <summary>
    /// Details (e-mail, post address, etc) for information delivery
    /// </summary>
    interface IAccountDeliveryDetails
    {
    }

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
    }
}
