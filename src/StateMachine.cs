using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace gvaduha.twofa
{

    interface IState
    {
        void Enter(Context ctx);
    }

    struct Transition
    {
        public readonly string Name;
        public readonly IState SourceState;
        public readonly IState TargetState;

        public Transition(string name, IState sourceState, IState targetState)
        {
            Name = name;
            SourceState = sourceState;
            TargetState = targetState;
        }
    }

    class Context
    {
        //TODO: plumb
        public TotpAuthenticationFactorConfig TotpConfig { get; } = TotpAuthenticationFactorConfig.Default;

        public TotpAuthenticationFactor AuthenticationFactor { get; } =
            new TotpAuthenticationFactor(TotpAuthenticationFactorConfig.Default);

        public IAccountScaDetails AccountScaDetails { get; } = new AccountScaDetails();
        public SharedSecretExchangeConfig SharedSecretExchangeConfig { get; } = SharedSecretExchangeConfig.Default;
        public ISharedSecretKeyDelivery SharedSecretKeyDelivery { get; } = new EmailGateWay();
        public IAccountDeliveryDetails AccountDeliveryDetails { get; } = new ApplicationUser();
        public IGraphicCodeGenerator GraphicCodeGenerator =>
            new QrCodeGenerator(new QrCodeGenerator.Config(TotpConfig.CodeSize, TotpConfig.CodeStep, "gv@local"));

        public string StateExecutionResult { get; set; } // consider Dictionary

    }

    class StateNotConfigured : IState
    {
        public void Enter(Context ctx)
        {
            Debug.Print($"Entered [{nameof(StateNotConfigured)}]");

            // generate and save share secret
            var ss = ctx.AuthenticationFactor.GenerateSharedSecret();
            ctx.AccountScaDetails.SharedSecret = ss;

            // encrypt shared secret with symmetric key
            var (ssEncrypted, iv, key) = ss.SymmetricCrypt((int) ctx.SharedSecretExchangeConfig.SymmetricKeySize);

            // send symmetric key to user
            ctx.SharedSecretKeyDelivery.SendSharedSecretKey(ctx.AccountDeliveryDetails, key);

            // create QR
            var visualCode = ctx.GraphicCodeGenerator.GenerateEncrypted(ssEncrypted, iv, ctx.AccountDeliveryDetails.Identity);

            ctx.StateExecutionResult = visualCode;

            // change state
            ctx.AccountScaDetails.Status = ScaFactorStatus.WaitingForConfirmation;
        }
    }

    class StateWaitingForConfirmation : IState
    {
        public void Enter(Context ctx)
        {
            Debug.Print($"Entered [{nameof(StateWaitingForConfirmation)}]");
            //TODO: Plumb
            ctx.StateExecutionResult = "<form><span>Verification code</span><input type='text'></form>";
        }
    }

    class StateEnabled : IState
    {
        public void Enter(Context ctx)
        {
            Debug.Print($"Entered [{nameof(StateWaitingForConfirmation)}]");
        }
    }

    class StateMachine
    {
        private readonly Dictionary<int, Transition> _trans = new Dictionary<int, Transition>();
        private IState _curState;

        public StateMachine(IState start)
        {
            _curState = start;
        }

        private int getKey(string name, IState sourceState)
        {
            return (name + sourceState.GetHashCode()).GetHashCode();
        }
        public StateMachine AddTransition(Transition trans)
        {
            _trans.Add(getKey(trans.Name, trans.SourceState), trans);
            return this;
        }

        public StateMachine Perform(string ev, Context ctx)
        {
            var transKey = getKey(ev, _curState);

            if (! _trans.ContainsKey(transKey) )
                throw new InvalidOperationException($"Invalid event {ev} for state {_curState.GetType().Name}");

            _curState = _trans[transKey].TargetState;
            _curState.Enter(ctx);

            return this;
        }
    }
}
