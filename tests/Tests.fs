namespace tests

open System
open System.Threading
open Microsoft.VisualStudio.TestTools.UnitTesting
open FsCheck
open gvaduha.twofa

[<TestClass>]
type TestTotpAuthenticationFactor () =

    let checkForAllSecrets fCheck sutcfg =
        let sut = new TotpAuthenticationFactor(sutcfg)
        let ssgen = Arb.from<string> |> Arb.filter (fun s -> (String.length s) = int sutcfg.SecretSize)

        Prop.forAll ssgen (fCheck sut)
        |> Check.QuickThrowOnFailure
        ()


    [<TestMethod>]
    member __.TestCorrectCodes () =
        let confgen = gen { let! l = Gen.choose (8, 64)
              return TotpAuthenticationFactorConfig(8uy, 30uy, 1uy, uint32 l) }
        let arbconf = confgen |> Arb.fromGen

        let correctCode (sut:TotpAuthenticationFactor) ss =
            let code = sut.GenerateTotp ss
            Assert.IsTrue (sut.VerifyTotp (ss, code))
            //printfn "ss:[%s] code:[%s]" ss code


        Prop.forAll arbconf (checkForAllSecrets correctCode)
        |> Prop.label ("Aggregate test for correct codes")
        |> Check.QuickThrowOnFailure
        ()


    [<TestMethod>]
    member __.TestExpiredCodes () =
        let incorrectCode (sut:TotpAuthenticationFactor) ss =
            let code = sut.GenerateTotp ss
            Thread.Sleep 1500 |> ignore
            Assert.IsFalse (sut.VerifyTotp (ss, code))
            //printfn "ss:[%s] code:[%s]" ss code

        let cfg = TotpAuthenticationFactorConfig(8uy, 1uy, 0uy, 32u)
        checkForAllSecrets incorrectCode cfg


    [<TestMethod>]
    member __.TestSecretGeneration () =
        let check size =
            let cfg = TotpAuthenticationFactorConfig(1uy,1uy,1uy,size)
            let sut = new TotpAuthenticationFactor(cfg)
            let ss = sut.GenerateSharedSecret ()
            Assert.AreEqual (uint32 (String.length ss), cfg.SecretSize)
            //printfn "%s" ss

        [1u..64u]
        |> Seq.map check
        |> Seq.toList
        |> ignore
        ()


[<TestClass>]
type TestStringSymCryptoExtensions () =
    [<TestMethod>]
    member __.TestWeCanDecryptEncryptedDataWithKeySizesUpTo128 () =
        let checker (keylen, text) =
            let x = StringSymCryptoExtensions.SymmetricCrypt (text, keylen)
            let (ctext, iv, key) = x.ToTuple ()
            let recovered = StringSymCryptoExtensions.SymmetricDecript (ctext, iv, key, 128)
            //printf "%A" recovered
            Assert.AreEqual (text, recovered)

        let testgen =
            let textgen = Arb.from<string> |> Arb.filter (fun s -> (String.length s) > 32) |> Arb.toGen
            let sizegen = Gen.choose (64, 128) |> Gen.filter (fun n -> n%16=0)
            let maket a b = (a, b)
            Gen.map2 maket sizegen textgen |> Arb.fromGen

        //testgen |> Gen.sample 1 100  |> printf "%A"
        
        Prop.forAll testgen checker
        |> Check.QuickThrowOnFailure
        ()
