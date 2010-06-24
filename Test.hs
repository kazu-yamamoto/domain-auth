{-# LANGUAGE OverloadedStrings #-}
module Test where

import qualified Data.ByteString.Lazy.Char8 as LC (pack,unpack)
import Data.IP
import Network.DNS as DNS hiding (answer)
import Network.DomainAuth
import Network.DomainAuth.DK.Types
import Network.DomainAuth.DKIM.Types
import Network.DomainAuth.PRD.Lexer
import Network.DomainAuth.Pubkey.RSAPub
import Test.Framework (defaultMain, testGroup, Test)
import Test.Framework.Providers.HUnit
import Test.HUnit hiding (Test)
import Text.Appar.String

tests :: [Test]
tests = [
    testGroup "SPF" [
         testCase "ipv4" test_ipv4
       , testCase "ipv4 2" test_ipv4_2
       , testCase "ipv6" test_ipv6
       , testCase "redirect" test_redirect
       , testCase "redirect2" test_redirect2
       , testCase "limit" test_limit
       , testCase "limit2" test_limit2
       , testCase "limit3" test_limit3
       ]
  , testGroup "Domain" [
         testCase "domain 1" test_domain1
       , testCase "domain 2" test_domain2
       , testCase "domain 3" test_domain3
       , testCase "domain 4" test_domain4
       ]
  , testGroup "PRD" [
         testCase "from" test_from
       , testCase "prd1" test_prd1
       , testCase "prd2" test_prd2
       , testCase "prd3" test_prd3
       , testCase "prd4" test_prd4
       , testCase "prd5" test_prd5
       , testCase "prd6" test_prd5
       , testCase "prd7" test_prd7
       , testCase "prd8" test_prd8
       , testCase "prd9" test_prd9
       ]
  , testGroup "Lexer" [
         testCase "structured 1" test_structured1
       , testCase "structured 2" test_structured2
       , testCase "structured 3" test_structured3
       , testCase "structured 4" test_structured4
       ]
  , testGroup "TaggedValue" [
         testCase "parse" test_parse
       , testCase "parse2" test_parse2
       ]
  , testGroup "Public Key" [
         testCase "lookup yahoo" test_lookup_yahoo
       , testCase "lookup gmail" test_lookup_gmail
       , testCase "lookup iij" test_lookup_iij
       ]
  , testGroup "Parser" [
         testCase "dk field" test_dk_field
       , testCase "dkim field" test_dkim_field
       , testCase "dkim field2" test_dkim_field2
       ]
  , testGroup "DK" [
         testCase "dk yahoo" test_dk_yahoo
       , testCase "dk gmail" test_dk_gmail
       ]
  , testGroup "Mail" [
         testCase "dk yahoo" test_mail
       , testCase "dk yahoo" test_mail2
       , testCase "dk yahoo" test_mail3
       ]
  ]

----------------------------------------------------------------

test_ipv4 :: Assertion
test_ipv4 = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF defaultLimit resolver "mew.org" ip >>= (@?= DAPass)
  where
    ip = IPv4 . read $ "202.232.15.101"

test_ipv4_2 :: Assertion
test_ipv4_2 = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF defaultLimit resolver "exapmle.org" ip >>= (@?= DATempError)
  where
    ip = IPv4 . read $ "192.0.2.1"

test_ipv6 :: Assertion
test_ipv6 = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF defaultLimit resolver "mew.org" ip >>= (@?= DAPass)
  where
    ip = IPv6 . read $ "2001:240:11e:c00::101"

test_redirect :: Assertion
test_redirect = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF defaultLimit resolver "gmail.com" ip >>= (@?= DAPass)
  where
    ip = IPv4 . read $ "72.14.192.1"

test_redirect2 :: Assertion
test_redirect2 = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF defaultLimit resolver "gmail.com" ip >>= (@?= DANeutral)
  where
    ip = IPv4 . read $ "72.14.128.1"

test_limit :: Assertion
test_limit = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF lim resolver "gmail.com" ip >>= (@?= DAPermError)
  where
    ip = IPv4 . read $ "72.14.192.1"
    lim = defaultLimit { ipv4_masklen = 24 }

test_limit2 :: Assertion
test_limit2 = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF defaultLimit resolver "nifty.com" ip >>= (@?= DAPass)
  where
    ip = IPv4 . read $ "202.248.236.1"

test_limit3 :: Assertion
test_limit3 = do
    rs <- makeResolvSeed defaultResolvConf
    withResolver rs $ \resolver ->
        runSPF lim resolver "nifty.com" ip >>= (@?= DAPass)
  where
    ip = IPv4 . read $ "202.248.88.1"
    lim = defaultLimit { limit = 2 }

----------------------------------------------------------------

test_domain1 :: Assertion
test_domain1 = extractDomain "Alice Brown <alice.brown@example.com>" @?= Just "example.com"

test_domain2 :: Assertion
test_domain2 = extractDomain "\"Alice . Brown\" <alice.brown@example.com> (Nickname here)" @?= Just "example.com"

test_domain3 :: Assertion
test_domain3 = extractDomain "alice.brown@example.com" @?= Just "example.com"

test_domain4 :: Assertion
test_domain4 = extractDomain "Alice Brown <example.com>" @?= Nothing

----------------------------------------------------------------

maddr1,maddr2,maddr3,maddr4 :: FieldValue
maddr1 = "alice@alice.example.jp"
maddr2 = "bob@bob.example.jp"
maddr3 = "chris@chris.example.jp"
maddr4 = "dave@dave.example.jp"

test_from :: Assertion
test_from = decideFrom (pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "alice.example.jp"

test_prd1 :: Assertion
test_prd1 = decidePRD (pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "alice.example.jp"

test_prd2 :: Assertion
test_prd2 = decidePRD (pushPRD "from" maddr1
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Nothing

test_prd3 :: Assertion
test_prd3 = decidePRD (pushPRD "sender" maddr2
                     $ pushPRD "from" maddr1
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "bob.example.jp"

test_prd4 :: Assertion
test_prd4 = decidePRD (pushPRD "sender" maddr2
                     $ pushPRD "sender" maddr2
                     $ pushPRD "from" maddr1
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Nothing

test_prd5 :: Assertion
test_prd5 = decidePRD (pushPRD "resent-from" maddr3
                     $ pushPRD "sender" maddr2
                     $ pushPRD "sender" maddr2
                     $ pushPRD "from" maddr1
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "chris.example.jp"

test_prd6 :: Assertion
test_prd6 = decidePRD (pushPRD "resent-sender" maddr4
                     $ pushPRD "resent-from" maddr3
                     $ pushPRD "sender" maddr2
                     $ pushPRD "sender" maddr2
                     $ pushPRD "from" maddr1
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "dave.example.jp"

test_prd7 :: Assertion
test_prd7 = decidePRD (pushPRD "resent-sender" maddr4
                     $ pushPRD "resent-from" maddr3
                     $ pushPRD "sender" maddr2
                     $ pushPRD "received" "dummy"
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "dave.example.jp"

test_prd8 :: Assertion
test_prd8 = decidePRD (pushPRD "resent-sender" maddr4
                     $ pushPRD "received" "dummy"
                     $ pushPRD "resent-from" maddr3
                     $ pushPRD "sender" maddr2
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
  where
   answer = Just "chris.example.jp"

test_prd9 :: Assertion
test_prd9 = decidePRD (pushPRD "received" "dummy"
                     $ pushPRD "resent-sender" maddr4
                     $ pushPRD "resent-from" maddr3
                     $ pushPRD "sender" maddr2
                     $ pushPRD "from" maddr1 initialPRD) @?= answer
 where
   answer = Just "dave.example.jp"

----------------------------------------------------------------

test_structured1 :: Assertion
test_structured1 = parse structured inp @?= out
  where
    inp = "From: Kazu Yamamoto (=?iso-2022-jp?B?GyRCOzNLXE9CSScbKEI=?=)\n <kazu@example.net>"
    out = Just ["From",":","Kazu","Yamamoto","<","kazu","@","example",".","net",">"]

test_structured2 :: Assertion
test_structured2 = parse structured inp @?= out
  where
    inp = "To:A Group(Some people)\n      :Chris Jones <c@(Chris's host.)public.example>,\n          joe@example.org,\n   John <jdoe@one.test> (my dear friend); (the end of the group)\n"
    out = Just ["To",":","A","Group",":","Chris","Jones","<","c","@","public",".","example",">",",","joe","@","example",".","org",",","John","<","jdoe","@","one",".","test",">",";"]

test_structured3 :: Assertion
test_structured3 = parse structured inp @?= out
  where
    inp = "Date: Thu,\n      13\n        Feb\n          1969\n      23:32\n               -0330 (Newfoundland Time)\n"
    out = Just ["Date",":","Thu",",","13","Feb","1969","23",":","32","-0330"]

test_structured4 :: Assertion
test_structured4 = parse structured inp @?= out
  where
    inp = "From: Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>\n"
    out = Just ["From",":","Pete","<","pete","@","silly",".","test",">"]

----------------------------------------------------------------

test_parse :: Assertion
test_parse = parseTaggedValue input @?= output
  where
    input = " k = rsa ; p= MIGfMA0G; n=A 1024 bit key;"
    output = [("k","rsa"),("p","MIGfMA0G"),("n","A1024bitkey")]

test_parse2 :: Assertion
test_parse2 = parseTaggedValue input @?= output
  where
    input = " k = \nrsa ;\n p= MIGfMA0G;\n n=A 1024 bit key"
    output = [("k","rsa"),("p","MIGfMA0G"),("n","A1024bitkey")]

----------------------------------------------------------------

test_lookup_yahoo :: Assertion
test_lookup_yahoo = do
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    pub0 <- readFile "data/yahoo.pub"
    DNS.withResolver rs $ \resolver -> do
        Just pub1 <- lookupPublicKey' resolver "dk200510._domainkey.yahoo.co.jp"
        LC.unpack pub1 @?= init pub0 -- removing "\n"

test_lookup_gmail :: Assertion
test_lookup_gmail = do
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    pub0 <- readFile "data/gmail.pub"
    DNS.withResolver rs $ \resolver -> do
        Just pub1 <- lookupPublicKey' resolver "gamma._domainkey.gmail.com"
        LC.unpack pub1 @?= init pub0 -- removing "\n"

test_lookup_iij :: Assertion
test_lookup_iij = do
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    pub0 <- readFile "data/iij.pub"
    DNS.withResolver rs $ \resolver -> do
        Just pub1 <- lookupPublicKey' resolver "omgo1._domainkey.iij.ad.jp"
        LC.unpack pub1 @?= init pub0 -- removing "\n"

----------------------------------------------------------------

test_dk_field :: Assertion
test_dk_field = parseDK inp @?= out
  where
    inp = "a=rsa-sha1; s=brisbane; d=football.example.com;\n  c=simple; q=dns;\n  b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZ\n    VoG4ZHRNiYzR;"
    out = Just DK {dkAlgorithm = DK_RSA_SHA1, dkSignature = "dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR", dkCanonAlgo = DK_SIMPLE, dkDomain0 = "football.example.com", dkFields = Nothing, dkSelector0 = "brisbane"}

test_dkim_field :: Assertion
test_dkim_field = parseDKIM inp @?= out
  where
   inp = "v=1; a=rsa-sha256; s=brisbane; d=example.com;\n         c=relaxed/simple; q=dns/txt; i=joe@football.example.com;\n         h=Received : From : To : Subject : Date : Message-ID;\n         bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\n         b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB\n           4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut\n           KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV\n           4bmp/YzhwvcubU4=;"
   out = Just DKIM {dkimVersion = "1", dkimSigAlgo = RSA_SHA256, dkimSignature = "AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHutKVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV4bmp/YzhwvcubU4=", dkimBodyHash = "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=", dkimHeaderCanon = DKIM_RELAXED, dkimBodyCanon = DKIM_SIMPLE, dkimDomain0 = "example.com", dkimFields = ["Received","From","To","Subject","Date","Message-ID"], dkimLength = Nothing, dkimSelector0 = "brisbane"}

test_dkim_field2 :: Assertion
test_dkim_field2 = parseDKIM inp @?= out
  where
   inp = "v=1; a=rsa-sha256; s=brisbane; d=example.com;\n         q=dns/txt; i=joe@football.example.com;\n         h=Received : From : To : Subject : Date : Message-ID;\n         bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\n         b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB\n           4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut\n           KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV\n           4bmp/YzhwvcubU4=;"
   out = Just DKIM {dkimVersion = "1", dkimSigAlgo = RSA_SHA256, dkimSignature = "AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHutKVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV4bmp/YzhwvcubU4=", dkimBodyHash = "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=", dkimHeaderCanon = DKIM_SIMPLE, dkimBodyCanon = DKIM_SIMPLE, dkimDomain0 = "example.com", dkimFields = ["Received","From","To","Subject","Date","Message-ID"], dkimLength = Nothing, dkimSelector0 = "brisbane"}

----------------------------------------------------------------

test_dk_yahoo :: Assertion
test_dk_yahoo = do
    mail <- readMail "data/yahoo"
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    DNS.withResolver rs $ \resolver -> do
        res <- runDK resolver mail
        res @?= DAPass

test_dk_gmail :: Assertion
test_dk_gmail = do
    mail <- readMail "data/gmail"
    rs <- DNS.makeResolvSeed DNS.defaultResolvConf
    DNS.withResolver rs $ \resolver -> do
        res <- runDK resolver mail
        res @?= DAPass
----------------------------------------------------------------

test_mail :: Assertion
test_mail = getMail inp @?= out
  where
    inp = LC.pack "from: val\nto: val\n\nbody"
    out = finalizeMail
        $ pushBody "body"
        $ pushField "to" "val"
        $ pushField "from" "val"
        initialMail

test_mail2 :: Assertion
test_mail2 = getMail inp @?= out
  where
    inp = LC.pack "from: val\tval\nto: val\n\nbody"
    out = finalizeMail
        $ pushBody "body"
        $ pushField "to" "val"
        $ pushField "from" "val\tval"
        initialMail

test_mail3 :: Assertion
test_mail3 = getMail inp @?= out
  where
    inp = LC.pack "from: val\nto: val\n"
    out = finalizeMail
        $ pushBody ""
        $ pushField "to" "val"
        $ pushField "from" "val"
        initialMail

----------------------------------------------------------------

main :: Assertion
main = defaultMain tests
