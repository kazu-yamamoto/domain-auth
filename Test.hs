{-# LANGUAGE OverloadedStrings #-}
module Test where

import Data.IP
import Network.DNS as DNS hiding (answer)
import Network.DomainAuth
import Network.DomainAuth.PRD.Lexer
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

main :: Assertion
main = defaultMain tests
