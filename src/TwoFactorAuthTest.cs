using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using gvaduha.twofa;
using Microsoft.FSharp.Core;

namespace gvaduha.tests.twofa
{
    static class FuncToFSharpExtensions
    {
        public static FSharpFunc<T1, TResult> ToFSharpFunc<T1, TResult>(this Func<T1, TResult> func)
            => FSharpFunc<T1, TResult>.FromConverter(val => func(val));
    }

    [TestClass]
    public class TwoFactorAuthTest
    {
        [TestMethod]
        public void Test()
        {
            Txxx.x();
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
