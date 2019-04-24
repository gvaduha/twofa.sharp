using System;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.FSharp.Core;
using gvaduha.twofa;

namespace gvaduha.tests.twofa
{
    static class FuncToFSharpExtensions
    {
        public static FSharpFunc<T1, TResult> ToFSharpFunc<T1, TResult>(this Func<T1, TResult> func)
            => FSharpFunc<T1, TResult>.FromConverter(val => func(val));
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

    class TestSimpleStateMachine
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
                .Perform("dance", ctx);
                //.Perform("restart", ctx);
        }
    }

    [TestClass]
    public class TwoFactorAuthTest
    {
        [TestMethod]
        public void Test()
        {
            TestSimpleStateMachine.x();
        }
    }

    //[TestClass]
    //public class TwoFactorAuthTest
    //{
    //    [TestMethod]
    //    public void Test()
    //    {
    //        var sutcfg = TotpAuthenticationFactorConfig.Default;
    //        var sut = new TotpAuthenticationFactor(sutcfg);
    //        Func<string, bool> sizeCheck = s => s.Length == sutcfg.SecretSize;
    //        //var nonEmptyGen = Arb.Default.String().Filter(s => s.Length > 30).Generator.ToArbitrary();//== sutcfg.SecretSize);
    //        var nonEmptyGen = Arb.Generate<string>().Where(s=>s.Length>32).ToArbitrary();//.Filter(s=>s.Length>32);
    //        //Arb.Generate<string>();

    //        var x = Gen.Sample(10, 300, nonEmptyGen.Generator);
            
    //        Func<string, bool> codeIsValid = ss =>
    //        {
    //            var code = sut.GenerateTotp(ss);
    //            return sut.VerifyTotp(ss, code);
    //        };
    //        Prop.ForAll(nonEmptyGen, codeIsValid)
    //            .Label($"Code is valid for all shared secrets of {sutcfg.SecretSize} size")
    //            .QuickCheckThrowOnFailure();

    //        //Gen.Sample(32, 10, nonEmptyGen).ToList().ForEach(x=>Console.WriteLine(x));
    //        //var u = sizecheck.tofsharpfunc();
    //        //var x = gen.where(u, arb.generate<string>());
    //        //var y = Gen.Sample(1, 1, x);
    //        //Console.WriteLine(y);
    //    }
    //}
}
