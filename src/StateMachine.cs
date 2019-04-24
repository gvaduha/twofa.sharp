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
        public TotpAuthenticationFactor AuthenticationFactor { get; } = new TotpAuthenticationFactor(TotpAuthenticationFactorConfig.Default);
        public IAccountScaDetails AccountScaDetails { get; } = new AccountScaDetails();
        public SharedSecretExchangeConfig SharedSecretExchangeConfig { get; } = SharedSecretExchangeConfig.Default;
        public ISharedSecretKeyDelivery SharedSecretKeyDelivery { get; } = new EmailGateWay();
        public IAccountDeliveryDetails AccountDeliveryDetails { get; } = new ApplicationUser();
    }

    class StateNotConfigured : IState
    {
        public void Enter(Context ctx)
        {
            string msg =
                "ENTER???";
            Debug.Print(msg);
        }
    }

    class StateConfigurationNotValidated : IState
    {
        public void Enter(Context ctx)
        {
            string msg =
                "QR = create (encSS)" +
                "present QR" +
                "save StateNotValidated";
            Debug.Print(msg);

            // generate and save share secret
            var ss = ctx.AuthenticationFactor.GenerateSharedSecret();
            ctx.AccountScaDetails.SharedSecret = ss;

            // encrypt shared secret with symmetric key
            var (ssEncrypted, iv, key) = ss.SymmetricCrypt((int) ctx.SharedSecretExchangeConfig.SymmetricKeySize);

            // send symmetric key to user
            ctx.SharedSecretKeyDelivery.SendSharedSecretKey(ctx.AccountDeliveryDetails, key);

            // create QR
        }
    }

    class StateEnabled : IState
    {
        public void Enter(Context ctx)
        {
            string msg =
                "" +
                "";
            Debug.Print(msg);
        }
    }

    class TestState<T> : IState
    {
        private T s;
        public TestState(T s)
        {
            this.s = s;
        }
        public void Enter(Context ctx)
        {
            Debug.Print("StateNotConfigured entered " + s.ToString());
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



    /****************************************************************************************************************************/

    class Txxx
    {
        public static void x()
        {
            IState st = new TestState<string>("start");
            IState sc = new TestState<string>("completed");
            IState sd = new TestState<string>("DANCING");

            var sm = new StateMachine(st)
                .AddTransition(new Transition("dance", st, sd))
                .AddTransition(new Transition("dance", sd, sd))
                .AddTransition(new Transition("finish", sd, sc))
                .AddTransition(new Transition("restart", sc, st));

            Context ctx = null;

            sm.Perform("dance", ctx)
                .Perform("dance", ctx)
                .Perform("finish", ctx)
                .Perform("restart", ctx)
                .Perform("dance", ctx)
                .Perform("dance", ctx)
                .Perform("restart", ctx);
        }
    }
}
